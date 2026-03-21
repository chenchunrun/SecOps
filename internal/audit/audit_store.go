package audit

import (
	"crypto/rand"
	"fmt"
	"sort"
	"sync"
	"time"
)

// InMemoryAuditStore 内存审计存储实现
type InMemoryAuditStore struct {
	mu     sync.RWMutex
	events map[string]*AuditEvent
	index  []string // 事件ID索引，按时间排序
}

// NewInMemoryAuditStore 创建内存审计存储
func NewInMemoryAuditStore() *InMemoryAuditStore {
	return &InMemoryAuditStore{
		events: make(map[string]*AuditEvent),
		index:  make([]string, 0),
	}
}

// SaveEvent 保存审计事件
func (s *InMemoryAuditStore) SaveEvent(event *AuditEvent) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	if event.ID == "" {
		event.ID = generateEventID()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.events[event.ID] = event
	s.index = append(s.index, event.ID)

	// 保持索引有序
	sort.SliceStable(s.index, func(i, j int) bool {
		return s.events[s.index[i]].Timestamp.Before(s.events[s.index[j]].Timestamp)
	})

	return nil
}

// GetEvent 获取审计事件
func (s *InMemoryAuditStore) GetEvent(id string) (*AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	event, exists := s.events[id]
	if !exists {
		return nil, fmt.Errorf("event not found: %s", id)
	}

	return event, nil
}

// ListEvents 列表查询
func (s *InMemoryAuditStore) ListEvents(filter *AuditFilter) ([]*AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*AuditEvent

	for _, id := range s.index {
		event := s.events[id]

		if !matchFilter(event, filter) {
			continue
		}

		results = append(results, event)
	}

	// 应用分页
	if filter.Limit > 0 {
		start := filter.Offset
		end := start + filter.Limit

		if start >= len(results) {
			return []*AuditEvent{}, nil
		}

		if end > len(results) {
			end = len(results)
		}

		return results[start:end], nil
	}

	return results, nil
}

// CountEvents 计数
func (s *InMemoryAuditStore) CountEvents(filter *AuditFilter) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0

	for _, id := range s.index {
		event := s.events[id]

		if matchFilter(event, filter) {
			count++
		}
	}

	return count, nil
}

// DeleteEvent 删除事件
func (s *InMemoryAuditStore) DeleteEvent(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.events[id]; !exists {
		return fmt.Errorf("event not found: %s", id)
	}

	delete(s.events, id)

	// 更新索引
	newIndex := make([]string, 0)
	for _, idx := range s.index {
		if idx != id {
			newIndex = append(newIndex, idx)
		}
	}
	s.index = newIndex

	return nil
}

// DeleteExpiredEvents 删除过期事件
func (s *InMemoryAuditStore) DeleteExpiredEvents(olderThan time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	idsToDelete := make([]string, 0)

	for _, id := range s.index {
		event := s.events[id]
		if now.Sub(event.Timestamp) > olderThan {
			idsToDelete = append(idsToDelete, id)
		}
	}

	for _, id := range idsToDelete {
		delete(s.events, id)
	}

	// 更新索引
	newIndex := make([]string, 0)
	for _, idx := range s.index {
		found := false
		for _, deleteID := range idsToDelete {
			if idx == deleteID {
				found = true
				break
			}
		}
		if !found {
			newIndex = append(newIndex, idx)
		}
	}
	s.index = newIndex

	return nil
}

// 辅助函数

// matchFilter 检查事件是否匹配过滤器
func matchFilter(event *AuditEvent, filter *AuditFilter) bool {
	// 时间范围
	if !filter.StartTime.IsZero() && event.Timestamp.Before(filter.StartTime) {
		return false
	}
	if !filter.EndTime.IsZero() && event.Timestamp.After(filter.EndTime) {
		return false
	}

	// 会话和用户
	if filter.SessionID != "" && event.SessionID != filter.SessionID {
		return false
	}
	if filter.UserID != "" && event.UserID != filter.UserID {
		return false
	}
	if filter.Username != "" && event.Username != filter.Username {
		return false
	}

	// 操作和资源
	if filter.EventType != "" && event.EventType != filter.EventType {
		return false
	}
	if filter.Action != "" && event.Action != filter.Action {
		return false
	}
	if filter.ResourceType != "" && event.ResourceType != filter.ResourceType {
		return false
	}
	if filter.ResourceName != "" && event.ResourceName != filter.ResourceName {
		return false
	}

	// 结果过滤
	if filter.Result != "" && event.Result != filter.Result {
		return false
	}

	// 风险评分
	if filter.MinRiskScore > 0 && event.RiskScore < filter.MinRiskScore {
		return false
	}

	return true
}

// generateEventID 生成事件ID（使用 crypto/rand UUID v4）
func generateEventID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// fallback to timestamp-based ID
		return fmt.Sprintf("evt_%d_%d", time.Now().Unix(), time.Now().Nanosecond())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 2
	return fmt.Sprintf("evt_%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

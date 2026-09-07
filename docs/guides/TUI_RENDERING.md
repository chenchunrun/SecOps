# Long reasoning in the TUI

While reasoning is streaming, a collapsed block larger than 8 KiB displays a
plain-text preview of its tail (up to 10 wrapped lines). The preview is labeled
explicitly: partial Markdown may begin inside a code fence or table and is not
parsed as a complete document.

Click the block or use the existing space-to-expand action to render the full
reasoning as Markdown. Full rendering also resumes when reasoning ends, the
answer starts, or generation is canceled. This presentation optimization does
not truncate stored messages, model context, or evidence.

Unchanged Markdown sections are cached separately so answer updates can reuse
reasoning output. Each section retains at most 512 KiB of source plus rendered
text; larger sections are rendered without this cache. This is not a global
conversation memory limit. Expanded and completed very large Markdown blocks
can still be expensive, and stripping ANSI from live input still reads the
entire reasoning string.

Run the synthetic rendering benchmarks from the module root:

```sh
go test ./internal/ui/chat -run '^$' -bench BenchmarkAssistant -benchmem -count=3
```

These measure individual render paths, not end-to-end TUI frame rates.

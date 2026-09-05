# Dependency license review

The dependency-review CI job checks changed Go and Python dependency manifests.
Its license allowlist is a repository intake policy, not a replacement for
complying with each dependency's license or reviewing a distribution's contents.
Unknown or unlisted licenses must still be reviewed; vulnerability checks remain
enabled independently.

## MIT-CMU and Pillow

Pillow 12.3.0 identifies its source license as MIT-CMU. The repository accepts
this permissive license, whose identifier is distinct from MIT and MIT-0.
When redistributing Pillow, preserve its copyright and license notices in copies
and supporting documentation. Do not use the copyright holder's or author's name
to advertise or publicize the distribution without the required prior written
permission. Preserve the upstream warranty and liability disclaimer.

This acceptance does not approve every third-party component that might be
bundled in a Pillow binary wheel; distributors must also retain and review those
components' applicable notices. Do not strip installed package license files.

Sources:

- [Pillow 12.3.0 license](https://github.com/python-pillow/Pillow/blob/12.3.0/LICENSE)
- [SPDX MIT-CMU text](https://spdx.org/licenses/MIT-CMU.html)

# Releasing Chaperone

How to cut a release, what to check before you publish it, and what "unsigned" means for the people who download it. The workflow is [`.github/workflows/release.yml`](../.github/workflows/release.yml). For the other workflows, read [development.md](development.md).

A release is a version tag. Pushing the tag starts the workflow. The workflow builds the programs and makes a **draft** GitHub release. It never publishes. A person checks the draft and publishes it.

## What a release holds

| File | System | Programs |
| --- | --- | --- |
| `chaperone_<tag>_windows_amd64.zip` | Windows, 64-bit Intel or AMD | `chapd.exe`, `chap.exe`, `chap-host.exe` |
| `chaperone_<tag>_linux_amd64.tar.gz` | Linux, 64-bit Intel or AMD | `chapd`, `chap` |
| `chaperone_<tag>_linux_arm64.tar.gz` | Linux, 64-bit ARM | `chapd`, `chap` |
| `chaperone_<tag>_darwin_arm64.tar.gz` | macOS, Apple silicon | `chapd`, `chap` |
| `chaperone_<tag>_darwin_amd64.tar.gz` | macOS, Intel | `chapd`, `chap` |
| `SHA256SUMS` | all | the SHA-256 of the five archives above |

Each archive holds one folder with the programs, `LICENSE`, `NOTICE` and `README.md`. `chap-host` is only in the Windows archive: it is the helper for the operator's own Windows session.

Every program is built with `CGO_ENABLED=0`, `-trimpath` and the version linker flags of `scripts/build.sh`: the version is the tag, and the commit is the commit of the tag. `chap version` prints both. The files in an archive carry the commit time, so building the same commit again gives the same archive.

## Cut a release

1. **Make sure `main` is good.** On the commit you will tag, these must be green: `ci` (all three jobs, because the Windows and macOS jobs run after a merge), `keyring` (it runs when `internal/vault` changed, and weekly; start it with `gh workflow run keyring -r main` if the last run is old) and the latest `scan`.
2. **Choose the version.** `vMAJOR.MINOR.PATCH`, for example `v0.2.0`. A release candidate is `v0.2.0-rc.1`; the draft is then marked as a pre-release. The workflow refuses any other shape.
3. **Tag the commit on `main` and push the tag.**

   ```bash
   git switch main && git pull --ff-only
   git tag -a v0.2.0 -m "v0.2.0"
   git push origin v0.2.0
   ```

4. **Wait for the `release` workflow** (Actions tab, about 10 minutes). It runs `verify` first: the tag must be a version, its commit must be on `main`, and `go vet` and `go test` must pass. Then it builds, checks that the Linux `chap` and `chapd` report the tag and the commit, and creates the draft.
5. **Check the draft** (next section), then publish it in the GitHub web page: **Releases**, the draft, **Edit**, **Publish release**.

To build a tag again by hand (Actions tab, **release**, **Run workflow**, and choose the tag in "Use workflow from"; or `gh workflow run release -r v0.2.0`) the earlier draft for that tag must be deleted first. The workflow does not replace a release that exists.

## What to check before you publish the draft

Do this on the draft, as a person. The workflow cannot judge these.

1. **The assets.** Six files: five archives and `SHA256SUMS`. The names have the tag you meant.
2. **The commit.** The body of the draft names the commit and the workflow run. It must be the commit you tagged.
3. **The checksums.** Download `SHA256SUMS` and at least the archive for the system you are on. Then check them:
   - Linux: `sha256sum -c --ignore-missing SHA256SUMS`
   - macOS: `shasum -a 256 -c --ignore-missing SHA256SUMS`
   - Windows: `Get-FileHash -Algorithm SHA256 .\chaperone_<tag>_windows_amd64.zip`, and compare with the line in `SHA256SUMS`.
4. **The version.** Unpack the archive and run `chap version`. It must print the tag and the first 12 characters of the commit, and the system and architecture of the archive. Do this on a Windows machine and on a Mac if you can; the workflow runs only the Linux one.
5. **On a Mac** (the one check no workflow does for the release file): unpack the `darwin_arm64` archive, run `codesign -dv ./chap` and read the output. On Apple silicon the system will not run code that has no signature at all, and the Go linker adds an *ad hoc* signature to these builds. Check that it did, and that `./chap version` runs. If it does not, do not publish the macOS archive until that is fixed.
6. **The notes.** The generated body says the programs are unsigned. Add what changed in this version, and anything an operator must do to upgrade (a migration, a changed flag). Keep the unsigned warning.
7. **Pre-release or not.** A tag with a `-` in it is marked as a pre-release. For any other tag, check that "Set as the latest release" is what you want.

If something is wrong, **delete the draft, delete the tag, fix, and tag again with a new version number if the tag was ever visible to others**:

```bash
gh release delete v0.2.0 --yes
git push --delete origin v0.2.0
git tag -d v0.2.0
```

Do not move a tag that has been published. A published tag is a promise about what the code was.

## The programs are not signed

The release has **no code signature on any program, and the checksums are not signed either**. Nobody has paid for a Developer ID certificate from Apple or a code-signing certificate for Windows, and the workflow has no secrets to sign with. What that means for the person who downloads it:

**macOS.** Gatekeeper checks programs that carry a quarantine flag. A web browser puts that flag on a file it downloads, and the flag stays on files that Archive Utility unpacks. Such a program does not open: the system says it "cannot be verified" or comes from an unidentified developer. Three ways out, from the safest:

- Download with `curl -LO` or `gh release download`. These tools do not set the flag, so the program runs.
- Remove the flag from a file you have decided to trust: `xattr -d com.apple.quarantine ./chap ./chapd`.
- Open **System Settings, Privacy & Security** after the first refusal and choose **Open Anyway** for that program.

The programs are not notarised, so the system has no Apple record of them. The ad hoc signature that the Go linker adds lets Apple silicon run them. It names no author and proves nothing about who built the file.

**Windows.** A file downloaded in a browser has a "mark of the web". The first run of `chapd.exe`, `chap.exe` or `chap-host.exe` shows Microsoft Defender SmartScreen: "Windows protected your PC", with the publisher "Unknown". The person chooses **More info**, then **Run anyway**. Or they remove the mark first, in PowerShell: `Get-ChildItem .\chaperone_* -Recurse | Unblock-File`. Windows 11 with **Smart App Control** on may refuse an unsigned program with no way to override; that setting must be off to run these. Unsigned, unknown programs are also more likely to be flagged by antivirus products as false positives. Say so in the release notes if a report comes in.

**Linux.** There is no gatekeeper. Check the checksum, then `chmod +x` if the file mode was lost.

**What the checksums give.** `SHA256SUMS` shows that a download is whole and is the file the release lists. It comes from the same page as the archives, so it does **not** prove who made them: a person who could replace an archive could replace the checksum file. The stronger check is to build from the tag yourself (`CHAP_VERSION=<tag> scripts/build.sh`, with the Go version in `go.mod`) and compare the programs. Whether the two builds are identical byte for byte has not been tested. Build provenance (GitHub artifact attestations) and signing are not set up. When they are, this page and `release.yml` change together.

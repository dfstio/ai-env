# This machine

- You run in a disposable AWS Lambda MicroVM; anything not committed to the working branch is lost when it terminates.
- Do not install system packages or change the machine's configuration.
- Commit your work to the current branch in small steps; the developer fetches it from the Mac.
- Never write credentials, tokens or keys to disk, into commits, or into command lines.

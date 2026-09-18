#!/bin/sh
# A script with a shebang, so that the execve of it opens /bin/sh first and the
# identity the sentry reports is the interpreter's and not this file's.
echo "from an interpreted script"

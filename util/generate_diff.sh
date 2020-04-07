#!/bin/bash
git diff --output=diff_tmp be5601e8260904c08071bbc087af1af81f3a7c80 HEAD -- ../winhttpd.c
echo -e '```diff' > portdiff.md
cat diff_tmp >> portdiff.md
echo -e '```' >> portdiff.md
rm diff_tmp

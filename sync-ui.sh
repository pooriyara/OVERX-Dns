#!/usr/bin/env bash
set -e
echo "Syncing shared/ui -> windows + android"
cp shared/ui/index.html windows/OVERX-Dns/ui/index.html
cp shared/ui/icon.png windows/OVERX-Dns/ui/icon.png
cp shared/ui/index.html android/app/src/main/assets/index.html
cp shared/ui/icon.png android/app/src/main/assets/icon.png
echo "Done"
ls -lh windows/OVERX-Dns/ui/ android/app/src/main/assets/

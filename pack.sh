#!/bin/bash

echo "Packing files..."
rm -rf ./b12901066/
mkdir b12901066
cp -r ./code ./b12901066/code
rm -f ./b12901066/code/test.sh
cp README.md ./b12901066/README.md
zip -r ./b12901066.zip ./b12901066/

echo "Finish Packing, list the result"
unzip -l ./b12901066.zip
ls -la demo.txt
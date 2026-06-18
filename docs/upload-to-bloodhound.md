# Upload To BloodHound

Manual upload is the default OpenIPAHound workflow.

1. Choose the OpenIPAHound schema file.

   Use `openipahound-extension.json` from this folder in BloodHound's
   extension-management UI.

   You can also regenerate the same schema from the CLI:

   ```bash
   openipahound schema export > openipahound-extension.json
   ```

2. Install or update that schema in BloodHound using the normal
   extension-management UI.
3. Collect payloads.

   ```bash
   openipahound collect ipa.example.test -d example.test -u openipahound-reader -p -o ./out
   openipahound validate ./out
   ```

4. Upload the JSON files in `./out` through BloodHound's normal file upload UI.
5. Optionally import saved queries from `queries/saved/`.

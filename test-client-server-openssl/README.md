## Testing tls client-server connection

#### Status
- Client Server communication works 

#### Todo
- Add mock/attestation extension

#### Files

`certs/ca` - here are located root ca certificates that our client application trusts

`certs/server` - here are server certificated signed by trusted ca 

`build.sh` - build sslecho 

`install-requirements.sh` - commands to install required libraries on Ubuntu

`certs/generate_certs.sh` - script to generate ca and server certificates
    - first cd to `certs/` directory and run from there

#### How to run bash script
Let's say you are trying to run bash script `script.sh` in the current directory

Change bash script to be executable
- `chmod +x script.sh`

Run the script
- `./script.sh`

#### Run test using sslecho executable `app/sslecho`

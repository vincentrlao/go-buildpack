# Cloud Foundry Go(Lang) Buildpack with Luna HSM Support

A Go buildpack with Luna client support (http://github.com/vincentrlao/go-buildpack/) for Go(lang) based apps that uses Luna HSM.

This is based on the cloudfoundry go-buildpack (https://github.com/cloudfoundry/go-buildpack) which is also based on [Heroku buildpack] (https://github.com/heroku/heroku-buildpack-go).

Note that this buildpack is currently not intended for public use. It is intended to be used by developers working on a proof-of-concept project.



## Usage

To use this buildpack, the app manifest must include the buildpack.

	buildpack: https://github.com/vincentrlao/go-buildpack

	
## Configuration
To use a standard Go app without Luna support, the manifest.yml only requires the following.

	env:
		GOVERSION: go1.6
		GOPACKAGENAME: your-package-name

To use this buildpack with Luna support, the following needs to be set in the app manifest.yml.

	services:
      - luna
	env:
		GOVERSION: go1.6
		GOPACKAGENAME: your-package-name
		ChrystokiConfigurationPath: /home/vcap/app/lunaclient

For specific use case (Test Peer-wallet mode), use the following:

	services:
      - luna
    env:
        GOVERSION: go1.6
        GOPACKAGENAME: github.com/hyperledger/fabric
        PEER_WALLET: true
        ChrystokiConfigurationPath: /home/vcap/app/lunaclient
        timeout: 180
        no_proxy: xip.io,bosh-lite.com,10.160.1.127
        NO_PROXY: xip.io,bosh-lite.com,10.160.1.127
        http_proxy: http://proxy-sg-singapore.gemalto.com:8080
        https_proxy: http://proxy-sg-singapore.gemalto.com:8080
        HTTP_PROXY: http://proxy-sg-singapore.gemalto.com:8080
        HTTPS_PROXY: http://proxy-sg-singapore.gemalto.com:8080
  

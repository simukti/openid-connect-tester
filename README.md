A simple web-based tester for [OpenID-Connect](https://openid.net/developers/how-connect-works/).

## Run via docker container

```
docker run --platform linux/amd64 -p 3000:3000 simukti/openid-connect-tester
```

Or customize server address bind using the `SERVER_ADDRESS` environment variable.

```
docker run --platform linux/amd64 -p 9000:9000 -e SERVER_ADDRESS=0.0.0.0:9000 simukti/openid-connect-tester
```

**NOTE**: This application only use in-memory storage and browser session during runtime.

## Web UI

### Configuration Page

![config](/assets/img/config.png)

### User Info Page

![config](/assets/img/user_info.png)

## LICENSE

[MIT](./LICENSE.txt)
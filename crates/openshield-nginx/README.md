# openshield-nginx

OpenShield as an nginx dynamic module, written in Rust with [ngx-rust](https://github.com/nginx/ngx-rust).

```nginx
load_module modules/libopenshield_nginx.so;

http {
    openshield_config /etc/openshield/waf.yaml;

    log_format waf '$remote_addr "$request" $status $openshield_action $openshield_rules $openshield_request_id';
    access_log /var/log/nginx/access.log waf;

    server {
        location / {
            openshield on;
            proxy_pass http://backend;
        }
    }
}
```

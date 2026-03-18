# Useful LogQL queries

## Detector alerts
```logql
{service_name="security-lab-detector"} | json
```

## All Nginx file logs
```logql
{job="security-lab-files", log_type="nginx"} | json
```

## Fake SSH failures from auth.log
```logql
{job="security-lab-files", log_type="auth"} |= "Failed password"
```

## Suspicious web paths by source IP
```logql
sum by (remote_addr) (
  count_over_time(
    {job="security-lab-files", log_type="nginx"}
    | json
    | path=~"/(\\.env|wp-login\\.php|server-status|admin|login|phpmyadmin).*"
    [5m]
  )
)
```

## HTTP 4xx burst by source IP
```logql
sum by (remote_addr) (
  count_over_time(
    {job="security-lab-files", log_type="nginx"}
    | json
    | status >= 400
    | status < 500
    [5m]
  )
)
```

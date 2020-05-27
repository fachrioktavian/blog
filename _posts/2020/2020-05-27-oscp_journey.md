---
layout: post
title: OSCP Journey
date: 2020-05-27 00:00:00
categories: 
    - other
tags:
    - oscp
    - linux
    - windows
---

![oscp_banner]({{ site.baseurl }}/images/posts/2020/other_1_1.png "oscp banner"){:width="600"}

## Try Harder !!!

That's what describe how i finally hand Offensive Security Certified Professional certificate. And that's what you need too if you plan to take this course or still in the middle of the course: The "Try Harder" mental.

### Start of Journey

PWK (Course of OSCP certification) is a course that i'd wanted to take when i was still in college 4 years ago. So why just take it now? is it cost to much? YES IT DOES. But believe me, it just worth it.

#### OSCP's student registration

In Feb 25th 2020 i decided to register as OSCP's student. Subscribed 2 months lab access cost me $1,199 or about Rp17,000,000 in my country and that was a lot of money thinking that a day before, it was only $999, just before PWK was updated to PWK2020. Good thing is it consists of many new materials including Active Directory which is not present before PWK2020.

The registration was quite easy. I fill online form in Offensive Security website, then received some emails describing what should i do next to complete the registration. I need to prepare a valid legal ID e.g passport to acknoledge it was me who really take the course, reduce possible act of cheating.

![registration]({{ site.baseurl }}/images/posts/2020/other_1_2.png "registration success")

#### VPN connection testing

![testing_vpn]({{ site.baseurl }}/images/posts/2020/other_1_3.png "vpn connection testing")

Next OffSec guides me to test VPN connection to PWK lab, troubleshoots if comes any trouble while connecting to the network. Connect to PWK lab was done with openvpn. And yes i need fast and stable internet connection. Please do not use your smartphone as hotspot as connection, in the lab you will need to do various enumeration that need stable connection. Bad connection will interfere your enumeration process.

#### Get the course material

![course_material]({{ site.baseurl }}/images/posts/2020/other_1_4.png "course material")

Upon the start of lab access at Mar 8th 2020, i received email containing course material in form of PDF and videos. it states that the link will expires in next 72 hours, additional copy in case i forgot to download will charges $199.

#### VMware virtual machine

Before taking the course, i've prepared a clean installed Kali linux as dual boot in my notebook. However OffSec gave custom vmware virtual machine image that is enhanced for PWK course. That makes it easy for me to manage everything because i got many problems while installing Kali my notebook regarding drivers and compatibility hardware. I recommend using given Kali virtual machine to advance into the lab.

![vmware_machine]({{ site.baseurl }}/images/posts/2020/other_1_5.png "vmware machine")

### The Lab

After watching some PWK videos, i realized that it will take long times to finish it all while lab time was running out. I've found and rooted some machine with same style like OSCP style in Hack The Box hacking platform, so it will be my first modal for the lab preparation. My strategy was going straight into the lab, if later find difficulties along the way, time to go back watch video and read course PDF.

In the end, i successfully rooted 47 machines including several labs in subsubnet of public network. Here some tips for working on the labs:

#### Leave port scanning and enumeration running at night

First, i listed all machines from student's control panel, then scheduled port scanning and enumeration using [AutoRecon](https://github.com/Tib3rius/AutoRecon). That's a very good tool, saving your times for enumerating services, it automates everything, run it then start doing something else. Normally, i left it runs when i was going to bed, checked the result on the next day, and if there was finished job, start working on the machine which all service was enumerated. Repeat the process.

#### Don't stick to one machine

If you stuck on a machine, don't force your body and brain to work on it. Yes you should have "Try Harder" mental, but it's good to have "Try Smarter" too. Move aside for a moment, have a break, eat some candies and drink water, your brain needs calories and your body should stay hydrated. Try hack another machine, sometimes a way into machine A is revealed from machine B.

#### Helpful friend is on the forum

Forum is a good place for you to find some answer to what holding you back in the lab. I asked something about the machine behavior and but not the way to hack the lab explicitly. The problems may come from exploit codes that need to enhanced a bit, it's okay to ask about it. People in forum may tell you that you need to edit something in order to make it work without ruining your joy by spoil you the credential or the complete walkthrough.

#### Friend outside the forum maybe helpful too

I have friends who already passed the OSCP certification, they are live PWK course. They help me providing some tips how to tackle obstacles in PWK lab.

#### You don't have to rooted all machines in the lab

There are many machines in the lab, especially PWK2020. You can see in the OffSec site there is additional 30% of course materials and lab machines. Previously, i had ambition to rooted all the machines, but actually it was not required to rooted them all. OffSec just need writeup of 10 lab's machine minimum + course PDF tasks to get addtional 5 points for exam result which later i didn't submit the lab report due to the amount of course PDF's tasks that are so many. The important thing is you learn how to hack them, the process of enumeration, the pace, and the time strategy are valuable things you need for the exam and for real life penetration testing too.

#### Take notes

I used Visual Studio Codes to create documentations for every rooted machine, that was a good way to review again some techniques i had done before. There are many tool for documentation, sublime, one note, cherry tree, etc. Take notes for every command you use. And bookmark all webpage regarding HowTos, tutorial, and anything related to the machine.

![take_notes]({{ site.baseurl }}/images/posts/2020/other_1_7.png "take notes"){:style="width:300px;"}

#### Create write-ups for every rooted machine

I created write-up for every machine i rooted. For some people, maybe creating documentation in detail is a boring activity, but for OSCP, you should get used to it. Even if you root all machines in Exam, but with no write-ups means no points for you, means you fail it.

#### Enjoy the process

Enjoy the learning process, the progress you've gotten from zero to little hero, from little hero to hero. Do not focus on the result, even the exam demands result, but the lab time is the study time, keep learn something, don't stop until the lab time is over.

#### Read other's OSCP notes

There are many notes, blogs, and tutorials available online that you can read and implement it in your lab. eg: [sushant747.gitbooks.io](https://sushant747.gitbooks.io/total-oscp-guide/), [securism.wordpress.com](https://securism.wordpress.com/oscp-notes-exploitation/), [book.hacktricks.xyz](https://book.hacktricks.xyz/), and many more.

### OSCP Exam

![oscp_exam]({{ site.baseurl }}/images/posts/2020/other_1_6.png "oscp exam")

My OSCP exam is scheduled at May 19th, 04:00. Yes 4 o'clock in the morning. I woke up at 03:00, take a shower, made a hot drink, and prepared snack. 15 minutes before the exam, i logged into proctoring webapps by OffSec. The proctor then asked me to show ID and what was around me. At 04:00 i received VPN connection to exam lab and my 23 hourse 45 minutes exam time was started.

I have 5 machines in the exam need to owned. 2 machines @ 25 points, 2 machines @ 20 points, and 1 @ 10 points with total points of 100. The minimum points to pass the exam is 70.

First machine i owned was buffer overflow machine @ 25 points. While doing exploit development, i left AutoRecon runs on the background to enumerates and scans services of 4 other machines. I finished owned BOF machine in an hour.

The next machine i targeted was 10 points machine. I thought it was an easy machine, turned out i spent 2 hours and get nothing. The exploit is available on the web, but try various versions of it didn't give me reverse shell. Maybe it was time to break, so i told the proctor i need to step aside from the monitor, drank water, got scretch and had a breakfast. An hour later i felt fresh again.

Back to my desk, told proctor i was ready to continue the exam then try a 20 points machine. Owned it about 2 hours later. So far i handed 45 points. After that i tried to continue my luck on 10 points machine. Decided to use forbidden tool aka metasploit and got the reverse shell instantly. I was very happy at that time thought my decision was right because i only got one chance to use metasploit, wether it success or not i couldn't use metasploit again on other machine. So far i handed 55 points and still have 12 hours to go. I took a break and lunch.

6 hours later i spent for 25 points machine. I found that this machine was easier than the 20 points one. Owned it and handed 80 points and 6 hours exam time left. That time i felt very relieved. I decided to use next 6 hours for writing documentation than continued to persue the 20 points machine. The target is to pass the minimum exam points, not to get full points. Last one hour i finally done all the documentation with 80 confident points. Such a nice experience :) even i didn't take a nap or sleep at night, stay awake for almost 24 hours.

After submitting the documentation, OffSec sent me a receipt of submitted document. At May 24th 2020 12:59 AM i received email from OffSec told me that i have successfully completed the PWK course and granted OSCP certification.

![oscp_success]({{ site.baseurl }}/images/posts/2020/other_1_8.png "oscp success")

### Last Word

PWK/OSCP is one of many security related course/certification out there. I can't compare it to another because this is my first certification. But after taking the course, i get many new knowledges, especially the pace to successfully exploit any target and "Try Harder" mental that actually become a mantra, a mantra to not give up on every situation, not only in hacking term but also in my real life itself :)

![quote]({{ site.baseurl }}/images/posts/2020/other_1_9.png "quote")

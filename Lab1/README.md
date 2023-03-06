<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en"><head>

<meta charset="utf-8">
<meta name="generator" content="quarto-1.2.269">

<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes">




</head>

<body class="fullcontent">

<div id="quarto-content" class="page-columns page-rows-contents page-layout-article">

<main class="content" id="quarto-document-content">

<header id="title-block-header" class="quarto-title-block default">
<div class="quarto-title">
<h1 class="title">Lab1</h1>
</div>



<div class="quarto-title-meta">

    
  
    
  </div>
  

</header>

<section id="системы-аутентификации-и-защиты-от-несанкционированного-доступа" class="level1">
<h1>Системы аутентификации и защиты от несанкционированного доступа</h1>
<p>Лабораторная работа №1</p>
<section id="цель" class="level2">
<h2 class="anchored" data-anchor-id="цель">Цель</h2>
<p>Вывести информацию о системе</p>
</section>
<section id="исходные-данные" class="level2">
<h2 class="anchored" data-anchor-id="исходные-данные">Исходные данные</h2>
<ol type="1">
<li>ОС Windows 10</li>
<li>RStudio Desktop</li>
<li>Интерпретатор языка R 4.2.2</li>
</ol>
</section>
<section id="план" class="level2">
<h2 class="anchored" data-anchor-id="план">План</h2>
<ol type="1">
<li>Выполнить команду system2(“systeminfo”, stdout = TRUE)</li>
<li>Выполнить команду system(“wmic cpu get name”)</li>
<li>Выполнить команду system(“powershell.exe Get-EventLog -LogName System -Newest 30”)</li>
</ol>
</section>
<section id="шаги" class="level2">
<h2 class="anchored" data-anchor-id="шаги">Шаги</h2>
<ol type="1">
<li>Сначала выполним команду system2(“systeminfo”, stdout = TRUE) для вывода информации о системе</li>
</ol>
<div class="cell">
<div class="sourceCode cell-code" id="cb1"><pre class="sourceCode r code-with-copy"><code class="sourceCode r"><span id="cb1-1"><a href="#cb1-1" aria-hidden="true" tabindex="-1"></a><span class="fu">system2</span>(<span class="st">"systeminfo"</span>, <span class="at">stdout =</span> <span class="cn">TRUE</span>)</span></code><button title="Copy to Clipboard" class="code-copy-button"><i class="bi"></i></button></pre></div>
<div class="cell-output cell-output-stdout">
<pre><code> [1] ""                                                                                           
 [2] "Host Name:                 LEON-LAPTOP"                                                     
 [3] "OS Name:                   Майкрософт Windows 10 Pro"                                       
 [4] "OS Version:                10.0.19045 N/A Build 19045"                                      
 [5] "OS Manufacturer:           Microsoft Corporation"                                           
 [6] "OS Configuration:          Standalone Workstation"                                          
 [7] "OS Build Type:             Multiprocessor Free"                                             
 [8] "Registered Owner:          Leon"                                                            
 [9] "Registered Organization:   "                                                                
[10] "Product ID:                00331-10000-00001-AA731"                                         
[11] "Original Install Date:     04.12.2022, 19:03:36"                                            
[12] "System Boot Time:          01.03.2023, 1:15:36"                                             
[13] "System Manufacturer:       HP"                                                              
[14] "System Model:              Victus by HP Laptop 16-e1xxx"                                    
[15] "System Type:               x64-based PC"                                                    
[16] "Processor(s):              1 Processor(s) Installed."                                       
[17] "                           [01]: AMD64 Family 25 Model 68 Stepping 1 AuthenticAMD ~3301 Mhz"
[18] "BIOS Version:              AMI F.12, 16.06.2022"                                            
[19] "Windows Directory:         C:\\Windows"                                                     
[20] "System Directory:          C:\\Windows\\system32"                                           
[21] "Boot Device:               \\Device\\HarddiskVolume2"                                       
[22] "System Locale:             ru;Russian"                                                      
[23] "Input Locale:              ru;Russian"                                                      
[24] "Time Zone:                 (UTC+03:00) Moscow, St. Petersburg"                              
[25] "Total Physical Memory:     15&nbsp;591 MB"                                                       
[26] "Available Physical Memory: 7&nbsp;801 MB"                                                        
[27] "Virtual Memory: Max Size:  27&nbsp;879 MB"                                                       
[28] "Virtual Memory: Available: 17&nbsp;551 MB"                                                       
[29] "Virtual Memory: In Use:    10&nbsp;328 MB"                                                       
[30] "Page File Location(s):     C:\\pagefile.sys"                                                
[31] "Domain:                    WORKGROUP"                                                       
[32] "Logon Server:              \\\\LEON-LAPTOP"                                                 
[33] "Hotfix(s):                 11 Hotfix(s) Installed."                                         
[34] "                           [01]: KB5022498"                                                 
[35] "                           [02]: KB5020613"                                                 
[36] "                           [03]: KB5011048"                                                 
[37] "                           [04]: KB5011069"                                                 
[38] "                           [05]: KB5012170"                                                 
[39] "                           [06]: KB5015684"                                                 
[40] "                           [07]: KB5022834"                                                 
[41] "                           [08]: KB5014032"                                                 
[42] "                           [09]: KB5016705"                                                 
[43] "                           [10]: KB5018506"                                                 
[44] "                           [11]: KB5020372"                                                 
[45] "Network Card(s):           4 NIC(s) Installed."                                             
[46] "                           [01]: Realtek Gaming GbE Family Controller"                      
[47] "                                 Connection Name: Ethernet"                                 
[48] "                                 Status:          Media disconnected"                       
[49] "                           [02]: MediaTek MT7921 Wi-Fi 6 802.11ax PCIe Adapter"             
[50] "                                 Connection Name: Беспроводная сеть"                        
[51] "                                 DHCP Enabled:    Yes"                                      
[52] "                                 DHCP Server:     192.168.1.254"                            
[53] "                                 IP address(es)"                                            
[54] "                                 [01]: 192.168.1.73"                                        
[55] "                                 [02]: fe80::482c:d44f:b2fa:cc88"                           
[56] "                           [03]: Windscribe VPN"                                            
[57] "                                 Connection Name: Подключение по локальной сети"            
[58] "                                 Status:          Media disconnected"                       
[59] "                           [04]: Windscribe Windtun420"                                     
[60] "                                 Connection Name: Подключение по локальной сети 2"          
[61] "                                 Status:          Media disconnected"                       
[62] "Hyper-V Requirements:      VM Monitor Mode Extensions: Yes"                                 
[63] "                           Virtualization Enabled In Firmware: Yes"                         
[64] "                           Second Level Address Translation: Yes"                           
[65] "                           Data Execution Prevention Available: Yes"                        </code></pre>
</div>
</div>
<p>2. Далее команда system(“wmic cpu get name”) для вывода информации о процессоре</p>
<div class="cell">
<div class="sourceCode cell-code" id="cb3"><pre class="sourceCode r code-with-copy"><code class="sourceCode r"><span id="cb3-1"><a href="#cb3-1" aria-hidden="true" tabindex="-1"></a><span class="fu">system2</span>(<span class="st">"cmd"</span>, <span class="at">args =</span> <span class="fu">c</span>(<span class="st">"/c"</span>, <span class="st">"wmic cpu get name"</span>), <span class="at">stdout =</span> <span class="cn">TRUE</span>)</span></code><button title="Copy to Clipboard" class="code-copy-button"><i class="bi"></i></button></pre></div>
<div class="cell-output cell-output-stdout">
<pre><code>[1] "Name                                    \r"
[2] "AMD Ryzen 5 6600H with Radeon Graphics  \r"
[3] "\r"                                        </code></pre>
</div>
</div>
<p>3. Также выполним команду system(“powershell.exe Get-EventLog -LogName System -Newest 30”) для вывода логов</p>
<div class="cell">
<div class="sourceCode cell-code" id="cb5"><pre class="sourceCode r code-with-copy"><code class="sourceCode r"><span id="cb5-1"><a href="#cb5-1" aria-hidden="true" tabindex="-1"></a><span class="fu">system2</span>(<span class="st">"powershell.exe"</span>, <span class="at">args =</span> <span class="fu">c</span>(<span class="st">"Get-EventLog"</span>, <span class="st">"-LogName"</span>, <span class="st">"System"</span>, <span class="st">"-Newest"</span>, <span class="st">"30"</span>), <span class="at">stdout =</span> <span class="cn">TRUE</span>)</span></code><button title="Copy to Clipboard" class="code-copy-button"><i class="bi"></i></button></pre></div>
<div class="cell-output cell-output-stdout">
<pre><code> [1] ""                                                                                                                           
 [2] "   Index Time          EntryType   Source                 InstanceID Message                                           "    
 [3] "   ----- ----          ---------   ------                 ---------- -------                                           "    
 [4] "    7120 мар 06 20:10  Warning     DCOM                        10016 The description for Event ID '10016' in Source ..."    
 [5] "    7119 мар 06 20:07  Warning     DCOM                        10016 The description for Event ID '10016' in Source ..."    
 [6] "    7118 мар 06 19:42  Warning     DCOM                        10016 The description for Event ID '10016' in Source ..."    
 [7] "    7117 мар 06 19:35  Warning     DCOM                        10016 The description for Event ID '10016' in Source ..."    
 [8] "    7116 мар 06 19:35  Information Microsoft-Windows...           16 The description for Event ID '16' in Source 'Mi..."    
 [9] "    7115 мар 06 19:25  Information Microsoft-Windows...           16 The description for Event ID '16' in Source 'Mi..."    
[10] "    7114 мар 06 19:11  Information Microsoft-Windows...           16 The description for Event ID '16' in Source 'Mi..."    
[11] "    7113 мар 06 19:02  Warning     DCOM                        10016 The description for Event ID '10016' in Source ..."    
[12] "    7112 мар 06 18:53  Information Microsoft-Windows...           16 The description for Event ID '16' in Source 'Mi..."    
[13] "    7111 мар 06 18:18  Information Microsoft-Windows...           16 The description for Event ID '16' in Source 'Mi..."    
[14] "    7110 мар 06 18:09  Information Microsoft-Windows...           19 Установка завершена: следующее обновление было ..."    
[15] "    7109 мар 06 18:08  Information Microsoft-Windows...           43 Установка начата: ОС Windows начала устанавлива..."    
[16] "    7108 мар 06 18:08  Information Microsoft-Windows...           44 Центр обновления Windows начал скачивать обновл..."    
[17] "    7107 мар 06 18:08  Warning     DCOM                        10016 The description for Event ID '10016' in Source ..."    
[18] "    7106 мар 06 18:07  Warning     DCOM                        10016 The description for Event ID '10016' in Source ..."    
[19] "    7105 мар 06 18:06  Information Microsoft-Windows...           16 The description for Event ID '16' in Source 'Mi..."    
[20] "    7104 мар 06 18:06  Information Microsoft-Windows...           16 The description for Event ID '16' in Source 'Mi..."    
[21] "    7103 мар 06 18:05  Information Microsoft-Windows...           16 The description for Event ID '16' in Source 'Mi..."    
[22] "    7102 мар 06 18:05  Warning     DCOM                        10016 The description for Event ID '10016' in Source ..."    
[23] "    7101 мар 06 18:05  Information Microsoft-Windows...           12 Процесс C:\\Program Files\\HP\\SystemOptimizer\\Sys..."
[24] "    7100 мар 06 18:05  Information Service Control M...   1073748864 Тип запуска службы \"Фоновая интеллектуальная сл..."   
[25] "    7099 мар 06 18:05  Information Microsoft-Windows...            1 Система вышла из состояния пониженного энергопо..."    
[26] "    7098 мар 06 18:05  Information Microsoft-Windows...         7001 Уведомление о входе пользователя для программы ..."    
[27] "    7097 мар 06 18:05  Information Microsoft-Windows...           27 The description for Event ID '27' in Source 'Mi..."    
[28] "    7096 мар 06 18:05  Information Microsoft-Windows...           25 The description for Event ID '25' in Source 'Mi..."    
[29] "    7095 мар 06 18:05  Information Microsoft-Windows...           32 The description for Event ID '32' in Source 'Mi..."    
[30] "    7094 мар 06 18:05  Information Microsoft-Windows...           18 The description for Event ID '18' in Source 'Mi..."    
[31] "    7093 мар 06 18:05  Information Microsoft-Windows...           30 The description for Event ID '30' in Source 'Mi..."    
[32] "    7092 мар 06 18:05  Information Microsoft-Windows...          105 The description for Event ID '105' in Source 'M..."    
[33] "    7091 мар 06 18:05  Information Microsoft-Windows...            1 Возможное обнаружение CVE: 2023-03-06T15:05:31...."    
[34] ""                                                                                                                           
[35] ""                                                                                                                           </code></pre>
</div>
</div>
</section>
<section id="оценка-результата" class="level2">
<h2 class="anchored" data-anchor-id="оценка-результата">Оценка результата</h2>
<p>В результате лабораторной работы мы получили основную информацию об ОС, процессоре и логи системы.</p>
</section>
<section id="вывод" class="level2">
<h2 class="anchored" data-anchor-id="вывод">Вывод</h2>
<p>Таким образом, мы научились работать с базовыми командами командой строки и получать информацию об операционной системе.</p>
</section>
</section>

</main>
<!-- /main column -->
</div> <!-- /content -->
</body></html>

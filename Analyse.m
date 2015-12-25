clear all; close all; clc;
% tcpdump文件
tcpdump_file = 'data.txt';
% 统计哪个方向（进入inout=0或发出inout=1）
inout = 0; 
% 本机mac地址（6字节）
host_mac = [hex2dec('00'), hex2dec('0C'), hex2dec('29'), hex2dec('32'), hex2dec('97'), hex2dec('77')]; 
% 对tcpdump文件进行预处理
preproc(tcpdump_file, host_mac);
% 统计
[ip_cnt, tcp_cnt, udp_cnt, ip_load, tcp_load, udp_load, ...
    ip_frags_total, ip_not_frag_cnt, ip_frag_cnt, ip_frag_percent, ...
    tcp_frag_percent, udp_frag_percent, ...
    ip_distri, tcp_distri, udp_distri, ...
    tcp_src_port_distri, tcp_des_port_distri, udp_src_port_distri, udp_des_port_distri, ...
    tcp_top10_src_port, tcp_top10_des_port, udp_top10_src_port, udp_top10_des_port, ...
    tcp_ctrl_percent] = proc(tcpdump_file, inout);
% 不同载荷饼图(分组和数据量)
figure; 
subplot(121); pie([tcp_cnt, udp_cnt, ip_cnt - tcp_cnt - udp_cnt], {'TCP', 'UDP', 'Others'});
subplot(122); pie([tcp_load, udp_load, ip_load - tcp_load - udp_load], {'TCP', 'UDP', 'Others'});
% ip分组片段
fprintf('total ip packets: %d\n ip fragments: %d\n ip packets segmented: %d\n', ip_cnt, ip_frags_total, ip_frag_cnt);
figure;
% tcp分组分片比例（当tcp_frag_percent不为0时再取消注释）
%subplot(121); pie([tcp_frag_percent], {'percent of TCP fragged'});
% udp分组分片比例(当实际抓到udp分组后再取消注释)
%subplot(122); pie([udp_frag_percent], {'percent of UDP fragged'});
% ip数据报累积分布曲线
figure;
plot(ip_distri(1, :), ip_distri(2, :), 'k-+');
figure;
subplot(121); plot(tcp_distri(1, :), tcp_distri(2, :), 'k-+');
%subplot(122); plot(udp_distri(1, :), udp_distri(2, :), 'k-+');
% tcp和udp端口分布直方图
figure;
subplot(221); plot(tcp_src_port_distri(1, :), tcp_src_port_distri(2, :), 'k-+');
subplot(222); plot(tcp_des_port_distri(1, :), tcp_des_port_distri(2, :), 'k-+');
%subplot(223); plot(udp_src_port_distri(1, :), udp_src_port_distri(2, :), 'k-+');
%subplot(224); plot(udp_des_port_distri(1, :), udp_des_port_distri(2, :), 'k-+');
% tcp前十端口
display(tcp_top10_src_port);
display(tcp_top10_des_port);
% udp前十端口
display(udp_top10_src_port);
display(udp_top10_des_port);
% 画出前十端口的ip数据包长度的累积分布曲线
inout_str = {'in ', 'out '};
src_des_str = {'source ', 'destination '};
tcp_udp_str = {'TCP ', 'UDP '};
% 这儿需要对tcp_top10_src_port,tcp_top10_des_port,udp_top10_src_port,udp_top10_des_port都做类似处理
for i = 0:1         % inout（0为进入分组，1为出去分组）
    for j = 1:length(tcp_top10_src_port)   % 更改这儿
        port_no = tcp_top10_src_port(j);
        distri = port_proc(tcpdump_file, port_no, i, 0, 0);
        if isempty(distri) continue; end;
        figure;
        title([inout_str{i + 1}, src_des_str{1}, tcp_udp_str{1}, 'port\_no =', num2str(port_no)]);
        plot(distri(1, :), distri(2, :), 'k-+');
    end  
end
% tcp各个控制位百分比
figure; pie(tcp_ctrl_percent, {'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN'});



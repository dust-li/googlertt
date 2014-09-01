#!/usr/bin/python
import os
import threading
import thread
import Queue
import re
import commands
import logging
import time
import traceback
import sys, getopt

'''
@Author: Dusk Lee
@Date: 2014.8.30

try IPs of google thought ping with multithread
google IPs from https://github.com/justjavac/Google-IPs

https://github.com/justjavac/Google-IPs/blob/master/README.md
'''

address_file = "GoogleIP.txt"
good_addrs_file = "good.txt"
log_file = "main.log"

# parameters
ping_cout = 8		# how many ping packets to be sent within a detection on an address
thread_num = 50		# how many threads will be used to do the job
is_fast_mode = True		# if set to true, only the first addr_num_in_network addresses will be detected, else all addresses will be detected
addr_num_in_network = 3		# how many addresses to detect in a network segment. the first add_num_in_network will be detected
sort_by = 1 # sort the result by: avg 1 / min 2/ max 3/ loss_rate 4

result = []
segment_dict = {}

#log
logging.basicConfig(filename = os.path.join(os.getcwd(), log_file), level = logging.DEBUG)  
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
logger = logging.getLogger("")
logger.addHandler(console)

#Allocate a lock
threadlock = thread.allocate_lock()


def usage():
	print '''useage: googleRTT.py [-hptmnsv]
-h, --help			show this help.
-t, --pingcount=NUMBER		how many ping packets to be sent within a detection on an address.
-m, --mode=fast|all 		which mode should the program run in
				if mode==fast, then only the first 'addressnumber' of address in a network segment
				will be detected. if mode==all, all addresses will be detected. The default mode is fast
				For now, only this two mode are supported.
-n, --addressnumber=NUMBER	determing how many addresses to detect in a network segment if 'fast' mode is set.
				the first addressnumber will be detected. The default is 10.
-s, --sortby=NUMBER		sort the result by ava/min/max/loss_rate. The following are options:
				1: avarage rtt
				2: minimum rtt 
				3: maximum rtt 
				4: packet loss rate
				the default is 1 (avarage).
'''


def get_network_addr_from_ip(ip):
	o = map(int, ip.split('.'))
	network_addr = (16777216 * o[0]) + (65536 * o[1]) + (256 * o[2])
	return network_addr

def is_address_good(address):
	# regular express
	ip_re = '((?:(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d))))'
	addrPattern = re.compile(ip_re)
	match = addrPattern.search(address)
	if match == None:
		logger.info("%s is not an ip address" %address)
		return False

	logger.debug("IP address: %s" %address)

	# is the address in the same network segment
	if is_fast_mode:
		net_addr = get_network_addr_from_ip(address)
		if segment_dict.get(net_addr):
			segment_dict[net_addr] += 1
			if segment_dict[net_addr] > addr_num_in_network:
				logger.debug("%s network segment packets: %s" %(net_addr,segment_dict[net_addr]))
				return False
			else:
				return True
		else:
			segment_dict[net_addr] = 1
			return True;
	
	return True

def ping_IP(ip):
	''' ping and get the result'''
	# return value. if packet_loss == 100%, return None
	# (ip,avg,min,max,packet_loss)

	(status, output) = commands.getstatusoutput("ping -c %s %s" %(ping_cout,ip))
	if status != 0:
		logger.info("PING %s Request timeout" %ip)
		return None
	logger.debug("ping %s success" %ip)

	s = output
	loss_rate = re.findall(r"packets received, (.+?)% packet loss", s)
	if(len(loss_rate) == 0):
		logger.warn("loss_rate not found")
		return None
	if(loss_rate[0] == '100.0'):
		return None

	min_rtt = re.findall(r"min/avg/max/stddev = (.+?)/",s)
	avg_rtt = re.findall((min_rtt[0]+"/(.+?)/"),s)
	max_rtt = re.findall((avg_rtt[0]+"/(.+?)/"),s)

	try:
		avg_rtt_float = float(avg_rtt[0])
		min_rtt_float = float(min_rtt[0])
		max_rtt_float = float(max_rtt[0])
		loss_rate_float = float(loss_rate[0])
		logger.debug("%s  %s  %s  %s %s" %(ip,avg_rtt_float,min_rtt_float,max_rtt_float,loss_rate_float))

		return (ip,avg_rtt_float,min_rtt_float,max_rtt_float,loss_rate_float)
	except:
		logger.exception("error parse: %s %s %s %s" %(avg_rtt[0],min_rtt[0],max_rtt[0],loss_rate[0]))
		return None



def do_job(i,q):
	while q.qsize() > 0:
		logger.debug("task left: %s" %q.qsize())

		ip=q.get()

		good_address = is_address_good(ip)
		if good_address == False:
			q.task_done()
			continue

		logger.debug("Thread %s: Pinging %s" %(i,ip))
		
		output = ping_IP(ip)

		if output:
			threadlock.acquire()
			result.append(output)
			threadlock.release()

		q.task_done()

	logger.debug("Thread %s done" %i)


def compare_result(x,y):
	''' compare to 'result' according to its loss_rate and the argument 'sort_by' '''

	if x[-1] < y[-1]:
		return -1
	elif x[-1] > y[-1]:
		return 1
	else:
		if x[sort_by] > y[sort_by]:
			return 1
		elif x[sort_by] < y[sort_by]:
			return -1
		else:
			return 0


def get_result_string(result):
	'''parse the 'result' in a string .
	'result' is in (ip,avg_rtt_float,min_rtt_float,max_rtt_float,loss_rate_float) format'''

	if len(result) > 0:
		result.sort(compare_result)
		str_header = '''    ip        avg       min      max  loss_rate\n'''
		str_res = str_header
		for i in result:
			for j in range(0,len(i)):
				str_res += (str(i[j]) + "  ")
			str_res += "\n"
		return str_res
	return None




def main(argv):

	#parse arguments
	try:
		opts, args = getopt.getopt(argv, "hp:t:m:n:s:v", ["help","pingcount==","threadnumber==","mode==","addressnumber==","sortby==","verbose"])
	except getopt.GetoptError as err:
		# print help information and exit:
		print str(err) # will print something like "option -a not recognized"
		usage()
		sys.exit(2)
	
	console.setLevel(logging.INFO)
	for opt, arg in opts:
		global ping_cout
		global is_fast_mode
		global thread_num
		global addr_num_in_network
		global sort_by

		if opt in ("-h", "--help"):
			usage()
			sys.exit()
		elif opt in ("-p", "--pingcount"):
			ping_cout  = int(arg)
		elif opt in ("-m", "--mode"):
			if arg == "fast" or arg == "f":
				is_fast_mode = True
			elif arg == "all" or arg == "a":
				is_fast_mode = False
			else:
				is_fast_mode = True
		elif opt in ("-t", "--threadnumber"):
			thread_num = int(arg)
		elif opt in ("-n", "--addressnumber"):
			addr_num_in_network = int(arg)
		elif opt in ("-s", "sortby"):
			sort_by = int(arg)
		elif opt in ("-v", "--verbose"):
			console.setLevel(logging.DEBUG)
		else:
			assert False, "unhandled option"

	logger.info("pingcout: %s" %ping_cout)
	logger.info("threadnumber: %s" %thread_num)
	logger.info("mode: %s" %("fast" if is_fast_mode else "all"))
	logger.info("addressnumber: %s" %addr_num_in_network)
	logger.info("sortby: %s" %sort_by)

	queue = Queue.Queue()

	# read file into address
	file_ip = None
	file_good = None
	file_bad = None
	try:
		file_ip = open(address_file,"r")
		file_good = open(good_addrs_file, "w")
	except IOError:
		print "file not exist"

	ip_addresses = file_ip.read().split()

	# filter the address
	# we need just try one address in a network segment
	for ip in ip_addresses:
		queue.put(ip)


	for i in range(thread_num):
		run=threading.Thread(target=do_job,args=(i,queue))
		run.setDaemon(False)
		run.start()
	queue.join()

	# write result to file
	str_res = get_result_string(result)
	if str_res:
		file_good.write(str_res)

	# clean
	file_ip.close()
	file_good.close()

	logger.info("All task done successfully!")

if __name__ == "__main__":
	main(sys.argv[1:])













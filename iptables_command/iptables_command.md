# iptables应用层命令解析
### 一、概述
netfilter/iptables 提供IP包过滤和防火墙配置功能，它由应用层的iptables和内核层的netfilter组成。防火墙在做包过滤时遵循一套规则，用户可以通过添加、编辑和移除规则达到管理包过滤的目的。
iptables作为应用层工具接收用户输入的命令，将其解析和验证后传输到内核netfilter模块进行处理。本文介绍应用层如何将iptables命令解析并传递到内核进行处理的。对于后续分析netfilter的实现机制有帮助。
### 二、iptables命令格式
iptables一般命令格式如下：
```
iptables [-t table] command [chain] [rules] [-j target]
```
* table-表
用于指定命令应用于哪个表，包活filter、nat、mangle和raw表。
* command-命令
-P或--policy  定义默认策略。
-L或--list  查看iptables规则列表。
-A或--append  在规则列表的最后增加1条规则。  
-I或--insert  在指定的位置插入1条规则。 
-D或--delete  从规则列表中删除1条规则。 
-R或--replace  替换规则列表中的某条规则。 
-F或--flush  删除表中所有规则。 
-Z或--zero  将表中数据包计数器和流量计数器归零。
-X或--delete-chain 删除链。
* chain-链
用于指定命令应用于哪条链，包括INPUT、OUTPUT、FORWARD、PREROUTING和POSTROUTING链。
* rules-规则
-i或--in-interface  <网络接口名>	指定数据包从哪个网络接口进入，如ppp0、eth0和eth1等。 
-o或--out-interface  <网络接口名>	指定数据包从哪块网络接口输出，如ppp0、eth0和eth1等。 
-p或---proto协议类型  < 协议类型>	指定数据包匹配的协议，如TCP、UDP和ICMP等。 
-s或--source  <源地址或子网>		   指定数据包匹配的源地址。 
--sport <源端口号>	指定数据包匹配的源端口号，可以使用“起始端口号	结束端口号”的格式指定一个范围的端口。 
-d或--destination <目标地址或子网>	指定数据包匹配的目标地址。 
--dport目标端口号	指定数据包匹配的目标端口号，可以使用“起始端口号	结束端口号”的格式指定一个范围的端口。
* target-动作
ACCEPT	接受数据包。 
DROP	丢弃数据包。 
REDIRECT	与DROP基本一样，区别在于它除了阻塞包之外， 还向发送者返回错误信息。 
SNAT	源地址转换，即改变数据包的源地址。 
DNAT	目标地址转换，即改变数据包的目的地址。 
MASQUERADE IP伪装，即NAT技术。 
LOG	日志功能，将符合规则的数据包的相关信息记录在日志中，以便管理员的分析和排错。
### 三、iptables命令行源码解析
本文解析的iptables版本为iptables-1.4.21，且只分析在IPV4协议下使用iptables配置规则流程。

![iptables命令解析](/home/maoyuan.li/netfilter/iptables_cmd_parse.jpg)
图1 iptables命令解析流程图

#### 1. iptables_main
iptables_main是iptables命令针对ipv4协议的main函数。
#### 2. xtables_init_all
xtables_init_all函数作用为初始化一些全局参数。调用xtables_init函数初始化xtables动态库位置(/usr/lib/iptables)。调用xtables_set_nfproto设置afinfo为ipv4协议。调用xtables_set_params设置iptables_globals全局参数，以及错误处理函数。
#### 3. init_extensions、init_extensions4
该函数调用init函数注册部分target和match。
值得一提的是init_extensions和init_extensions4都是由"extensions/GNUmakefile.in"生成的。
BUILTIN_MODULES宏值为：
```
standard icmp tcp udp comment id set SET limit mac multiport comment LOG \
TCPMSS REJECT time mark MARK icmp6 REJECT state iptable_raw CT conntrack \
SNAT DNAT MASQUERADE REDIRECT
```
该宏指定需要静态init的模块。
```
extensions/GNUmakefile
#保存extensions目录下BUILTIN_MODULES指定需要初始化的match或者target。
fx_build_static := $(filter $(BUILTIN_MODULES),${pfx_build_mod} 
#为pfx_build_static加上前缀的"xt_"的值。
initext_func := $(addprefix xt_,${pfx_build_static})
#最后生成init_extensions函数：
for i in ${initext_func}; do \
	echo "extern void lib$${i}_init(void);" >>$@; \
done; \
echo "void init_extensions(void);" >>$@; \
echo "void init_extensions(void)" >>$@; \
echo "{" >>$@; \
for i in ${initext_func}; do \
	echo  " ""lib$${i}_init();" >>$@; \
done; \
echo "}" >>$@; \
```
由此可知iptables源码中extensions目录下模块分为了两种，一种是静态编译进iptables中的(在函数init_extensions和init_extensions4中初始化)，另一种是以动态库的形式存在编译生成.so文件(路由器"/usr/lib/iptables"目录)，iptables运行时动态加载。
#### 4. do_command4
do_command4函数的作用是解析和校验命令行参数并将其保存到handle结构体指针中。

![do_command4函数](/home/maoyuan.li/netfilter/do_command.png)
图2 do_command4函数流程图

###### 1)清除match和target的标志位
```
iptables/iptables.c do_command4()
	for (m = xtables_matches; m; m = m->next)
		m->mflags = 0;

	for (t = xtables_targets; t; t = t->next) {
		t->tflags = 0;
		t->used = 0;
	}
```
###### 2)通过getopt_long循环读取iptables命令行参数进行解析
```
iptables/iptables.c do_command4()
	while ((cs.c = getopt_long(argc, argv,
	   "-:A:C:D:R:I:L::S::M:F::Z::N:X::E:P:Vh::o:p:s:d:j:i:fbvwnt:m:xc:g:46",
					   opts, NULL)) != -1) {
		switch (cs.c) {
		case 'A':   //添加规则，add_command将规则保存到command中
			add_command(&command, CMD_APPEND, CMD_NONE,
				    cs.invert);
			chain = optarg;
            ......
		case 'p':   //指定协议，通过set_option标记协议字段到cs.options并协议类型保存到cs.fw.ip.proto中
			set_option(&cs.options, OPT_PROTOCOL, &cs.fw.ip.invflags,
				   cs.invert);

			/* Canonicalize into lower case */
			for (cs.protocol = optarg; *cs.protocol; cs.protocol++)
				*cs.protocol = tolower(*cs.protocol);

			cs.protocol = optarg;
			cs.fw.ip.proto = xtables_parse_protocol(cs.protocol);

			if (cs.fw.ip.proto == 0
			    && (cs.fw.ip.invflags & XT_INV_PROTO))
				xtables_error(PARAMETER_PROBLEM,
					   "rule would never match protocol");
			break;
            ......
		case 's':   //标记源地址到cs.options中，并将源IP地址保存到shstnetworkmask中
			set_option(&cs.options, OPT_SOURCE, &cs.fw.ip.invflags,
				   cs.invert);
			shostnetworkmask = optarg;
			break;
            ......
		case 'j':   //指定匹配后的target
			command_jump(&cs);
			break;
		case 'i':   //标记数据包进入的接口，并将接口保存到cs.fw.ip.iniface中
			if (*optarg == '\0')
				xtables_error(PARAMETER_PROBLEM,
					"Empty interface is likely to be "
					"undesired");
			set_option(&cs.options, OPT_VIANAMEIN, &cs.fw.ip.invflags,
				   cs.invert);
			xtables_parse_interface(optarg,
					cs.fw.ip.iniface,
					cs.fw.ip.iniface_mask);
			break;
            ......
		case 'm':   //规则中指定的match规则
			command_match(&cs);
			break;
            ......
		case 't':   //指定对哪个表进行操作，默认为filter表
			if (cs.invert)
				xtables_error(PARAMETER_PROBLEM,
					   "unexpected ! flag before --table");
			*table = optarg;
			break;
            ......
		default:    //对其他参数进行解析
			if (command_default(&cs, &iptables_globals) == 1)
				/* cf. ip6tables.c */
				continue;
			break;
		}
```
while循环对所有的参数进行处理，保存到对应的结构体中:
```
iptables/iptables.c do_command4()
unsigned int command = 0; //作为add_command的参数保存命令。
```
```
iptables/xshared.h
struct iptables_command_state {
	union {
		struct ipt_entry fw; //ipv4对应的规则结构体
		struct ip6t_entry fw6;  //ipv6对应的规则结构体
	};
	int invert; //是否带有翻转符号'!'
	int c; //保存getopt_long的返回值
	unsigned int options; //保存命令中包含哪些选项
	struct xtables_rule_match *matches; //对应的match规则
	struct xtables_target *target; //对应的target规则
	char *protocol; //对应的协议
	int proto_used; //协议是否被加载过
	const char *jumpto; //保存匹配规则后的目标
	char **argv; //保存argv参数
} cs;
```
其中fw对应的结构体为：
```
include/linux/netfilter_ipv4/ip_tables.h
struct ipt_entry { //保存一条ipv4规则
	struct ipt_ip ip; //源、目的地址、协议、接口

	/* Mark with fields that we care about. */
	unsigned int nfcache;

	/* Size of ipt_entry + matches */
	u_int16_t target_offset;  //target结构对应的偏移地址
	/* Size of ipt_entry + matches + target */
	u_int16_t next_offset;  //下一条规则的偏移地址

	/* Back pointer */
	unsigned int comefrom;

	/* Packet and byte counters. */
	struct xt_counters counters; //数据包的计数值

	/* The matches (if any), then the target. */
	unsigned char elems[0]; //match和target结构保存的地址
};
```

![ipt_entry结构](/home/maoyuan.li/netfilter/ipt_entry.jpg)
图3 ipt_entry函数流程图

match和target能够以.so库的形式加载，其中一条规则里面可以有多个match但是只有一个target。
对于不能识别的参数使用command_default函数进行解析，该函数会根据已经加载的match和target去对参数进行解析，如果没有match加载，则根据proto加载相应的match对参数进行解析。
```
iptables/xshared.c
int command_default(struct iptables_command_state *cs,
		    struct xtables_globals *gl)
{
    ......
	if (cs->target != NULL && //尝试通过已经加载的target解析参数
	    (cs->target->parse != NULL || cs->target->x6_parse != NULL) &&
	    cs->c >= cs->target->option_offset &&
	    cs->c < cs->target->option_offset + XT_OPTION_OFFSET_SCALE) {
		xtables_option_tpcall(cs->c, cs->argv, cs->invert,
				      cs->target, &cs->fw);
		return 0;
	}
	for (matchp = cs->matches; matchp; matchp = matchp->next) { //如果有相应的match使用扩展的match去处理。
		m = matchp->match;
        ......
		if (cs->c < matchp->match->option_offset ||
		    cs->c >= matchp->match->option_offset + XT_OPTION_OFFSET_SCALE)
			continue;
		xtables_option_mpcall(cs->c, cs->argv, cs->invert, m, &cs->fw);
		return 0;
	}
	/* Try loading protocol */
	m = load_proto(cs); //根据proto加载对应的match对参数进行解析
	if (m != NULL) {
		cs->proto_used = 1;
        ......
		optind--; //加载match后重新解析该参数
		/* Indicate to rerun getopt *immediately* */
 		return 1;
	}
    ......
}
```
###### 3)对输入参数的组合进行逻辑校验
```
iptables/iptables.c do_command4()
	if (strcmp(*table, "nat") == 0 &&
	    ((policy != NULL && strcmp(policy, "DROP") == 0) ||
	    (cs.jumpto != NULL && strcmp(cs.jumpto, "DROP") == 0)))
		xtables_error(PARAMETER_PROBLEM,
			"\nThe \"nat\" table is not intended for filtering, "
		        "the use of DROP is therefore inhibited.\n\n");
        ......
//对源地址和目的地址进行解析的函数
	if (shostnetworkmask)
		xtables_ipparse_multiple(shostnetworkmask, &saddrs,
					 &smasks, &nsaddrs);

	if (dhostnetworkmask)
		xtables_ipparse_multiple(dhostnetworkmask, &daddrs,
					 &dmasks, &ndaddrs);
```
###### 4)从内核中读取指定表的所有链和规则
```
iptables/iptables.c do_command4()
	if (!*handle)
		*handle = iptc_init(*table); //从内核获取table对应的链和规则

	/* try to insmod the module if iptc_init failed */ //失败加载模块后重新读取table规则
	if (!*handle && xtables_load_ko(xtables_modprobe_program, false) != -1)
		*handle = iptc_init(*table);
```
iptc_init定义如下：        
```
libiptc/libip4tc.c
#define TC_INIT			iptc_init
```
```
libiptc/libiptc.c
struct xtc_handle *
TC_INIT(const char *tablename)
{
	struct xtc_handle *h;
	STRUCT_GETINFO info;
	unsigned int tmp;
	socklen_t s;
	int sockfd;
    ......
	sockfd = socket(TC_AF, SOCK_RAW, IPPROTO_RAW);

	s = sizeof(info);

	strcpy(info.name, tablename);
    //通过getsockopt从内核获取指定表的基本信息，有表占用的空间、规则的数目等信息。
	if (getsockopt(sockfd, TC_IPPROTO, SO_GET_INFO, &info, &s) < 0) {
		close(sockfd);
		return NULL;
	}
    //分配空间保存表的规则
	if ((h = alloc_handle(info.name, info.size, info.num_entries))
	    == NULL) {
		close(sockfd);
		return NULL;
	}

	/* Initialize current state */
	h->sockfd = sockfd;
	h->info = info;

	h->entries->size = h->info.size;

	tmp = sizeof(STRUCT_GET_ENTRIES) + h->info.size;

    //通过getsockopt从内核获取所有表的数据
	if (getsockopt(h->sockfd, TC_IPPROTO, SO_GET_ENTRIES, h->entries,
		       &tmp) < 0)
		goto error;
    ......
    //解析内核传递的表的规则将其解析后保存到struct xtc_handle结构体中
	if (parse_table(h) < 0)
		goto error;

	CHECK(h); //对表进行校验
	return h;
    ......
}
```
xtc_handle结构体内容从内核中读取并填充，它保存iptables指定表的链和规则。
```
libiptc/libiptc.c
struct xtc_handle {
	int sockfd;   //与内核通信的套接字
	int changed;	 /* Have changes been made? */

	struct list_head chains;

	struct chain_head *chain_iterator_cur; //当前指向的链
	struct rule_head *rule_iterator_cur; //当前指向的规则

	unsigned int num_chains;     /* number of user defined chains */

	struct chain_head **chain_index;  /* array for fast chain list access*/
	unsigned int   chain_index_sz;/* size of chain index array */

	int sorted_offsets; /* if chains are received sorted from kernel,
			     * then the offsets are also sorted. Says if its
			     * possible to bsearch offsets using chain_index.
			     */

	STRUCT_GETINFO info; //保存内核传递过来的info信息
	STRUCT_GET_ENTRIES *entries;//保存内核传递的所有表的数据
};
```
struct chain_head用于保存用户自定义链和系统标准链。
```
libiptc/libiptc.c
struct chain_head
{
	struct list_head list;
	char name[TABLE_MAXNAMELEN]; //表的名字
	unsigned int hooknum;		/* hook number+1 if builtin */
	unsigned int references;	/* how many jumps reference us */
	int verdict;			/* verdict if builtin */

	STRUCT_COUNTERS counters;	/* per-chain counters */
	struct counter_map counter_map;

	unsigned int num_rules;		//该链的规则数目
	struct list_head rules;		//指向链对应的第一条规则

	unsigned int index;		/* index (needed for jump resolval) */
	unsigned int head_offset;	/* offset in rule blob */
	unsigned int foot_index;	/* index (needed for counter_map) */
	unsigned int foot_offset;	/* offset in rule blob */
};
```
struct rule_head用于保存规则链表，方便对规则进行管理
```
libiptc/libiptc.c
struct rule_head
{
	struct list_head list;
	struct chain_head *chain; //该规则对应的链
	struct counter_map counter_map;

	unsigned int index;		/* index (needed for counter_map) */
	unsigned int offset;		/* offset in rule blob */

	enum iptcc_rule_type type;
	struct chain_head *jump;	//如果是IPTCC_R_JUMP类型的target，保存跳转到的链地址

	unsigned int size;		/* size of entry data */
	STRUCT_ENTRY entry[0]; //指向具体的规则
};
```
parse_table()函数用来解析内核传递的表信息，解析出链和链包含的规则。
```
libiptc/libiptc.c
/* parse an iptables blob into it's pieces */
static int parse_table(struct xtc_handle *h)
{
	STRUCT_ENTRY *prev;
	unsigned int num = 0;
	struct chain_head *c;

	/* First pass: over ruleset blob */
    //对内核传递的每条规则都调用cache_add_entry进行解析
	ENTRY_ITERATE(h->entries->entrytable, h->entries->size,
			cache_add_entry, h, &prev, &num);

	/* Build the chain index, used for chain list search speedup */
    //创建链对应的表索引结构
	if ((iptcc_chain_index_alloc(h)) < 0)
		return -ENOMEM;
    //填充整个链表索引信息
	iptcc_chain_index_build(h);

	/* Second pass: fixup parsed data from first pass */
    //将一些target为用户自定义链的规则指针重定向
	list_for_each_entry(c, &h->chains, list) {
		list_for_each_entry(r, &c->rules, list) {
			if (r->type != IPTCC_R_JUMP)
				continue;

			t = (STRUCT_STANDARD_TARGET *)GET_TARGET(r->entry);
			lc = iptcc_find_chain_by_offset(h, t->verdict);
			if (!lc)
				return -1;
			r->jump = lc;
		}
	}
	return 1;
}
cache_add_entry函数将STRUCT_ENTR结构解析为规则或者链保存到struct xtc_handle中。
/* main parser function: add an entry from the blob to the cache */
static int cache_add_entry(STRUCT_ENTRY *e,
			   struct xtc_handle *h,
			   STRUCT_ENTRY **prev,
			   unsigned int *num)
{
	unsigned int builtin;
	unsigned int offset = (char *)e - (char *)h->entries->entrytable;
    //用户自定义链
	if (strcmp(GET_TARGET(e)->u.user.name, ERROR_TARGET) == 0) {
        //分配链空间
		struct chain_head *c =
			iptcc_alloc_chain_head((const char *)GET_TARGET(e)->data, 0);
		if (!c) {
			errno = -ENOMEM;
			return -1;
		}
		h->num_chains++; /* New user defined chain */
        //添加链到h->chains中
		__iptcc_p_add_chain(h, c, offset, num);
    //hook点即系统标准的链
	} else if ((builtin = iptcb_ent_is_hook_entry(e, h)) != 0) {
		struct chain_head *c =
			iptcc_alloc_chain_head((char *)hooknames[builtin-1],
						builtin);
		if (!c) {
			errno = -ENOMEM;
			return -1;
		}

		c->hooknum = builtin;

        //添加链到h->chains中
		__iptcc_p_add_chain(h, c, offset, num);
		goto new_rule;
	} else {
        //正常的规则
		struct rule_head *r;
new_rule:
        //分配保存规则的空间
		if (!(r = iptcc_alloc_rule(h->chain_iterator_cur,
					   e->next_offset))) {
			errno = ENOMEM;
			return -1;
		}

		r->index = *num; //规则索引
		r->offset = offset; //该规则的偏移量
		memcpy(r->entry, e, e->next_offset);//拷贝内核传递的规则数据
		r->counter_map.maptype = COUNTER_MAP_NORMAL_MAP;//map类型
		r->counter_map.mappos = r->index; //链索引

		/* handling of jumps, etc. */ //处理target
		if (!strcmp(GET_TARGET(e)->u.user.name, STANDARD_TARGET)) {
			STRUCT_STANDARD_TARGET *t;

			t = (STRUCT_STANDARD_TARGET *)GET_TARGET(e);

			if (t->verdict < 0) { //标准的target
				DEBUGP_C("standard, verdict=%d\n", t->verdict);
				r->type = IPTCC_R_STANDARD;
			} else if (t->verdict == r->offset+e->next_offset) {
				DEBUGP_C("fallthrough\n"); //落空即无target
				r->type = IPTCC_R_FALLTHROUGH;
			} else { //跳转到其他用户自定义链
				DEBUGP_C("jump, target=%u\n", t->verdict);
				r->type = IPTCC_R_JUMP;
			}
		} else { //target是用户自定义target
			DEBUGP_C("module, target=%s\n", GET_TARGET(e)->u.user.name);
			r->type = IPTCC_R_MODULE;
		}

        //将规则添加到h结构的链表中
		list_add_tail(&r->list, &h->chain_iterator_cur->rules);
		h->chain_iterator_cur->num_rules++; //规则数目加1
	}
out_inc:
	(*num)++; //计数值加1
	return 0;
}
```
###### 5)修改struct xtc_handle内容
从内核读取完信息后再次对输入参数的逻辑性做一些校验。
```
iptables/iptables.c do_command4()
	if (command == CMD_APPEND
	    || command == CMD_DELETE
	    || command == CMD_CHECK
	    || command == CMD_INSERT
	    || command == CMD_REPLACE) {//PREROUTING和INPUT链不能指定数据包出去的接口
		if (strcmp(chain, "PREROUTING") == 0
		    || strcmp(chain, "INPUT") == 0) {
			/* -o not valid with incoming packets. */
			if (cs.options & OPT_VIANAMEOUT)
				xtables_error(PARAMETER_PROBLEM,
					   "Can't use -%c with %s\n",
					   opt2char(OPT_VIANAMEOUT),
					   chain);
		}
        ......
		e = generate_entry(&cs.fw, cs.matches, cs.target->t);//将match和target信息保存到cs.fw结构中

	switch (command) {
	case CMD_APPEND: //添加规则
		ret = append_entry(chain, e,
				   nsaddrs, saddrs, smasks,
				   ndaddrs, daddrs, dmasks,
				   cs.options&OPT_VERBOSE,
				   *handle);
		break;
	case CMD_DELETE://删除规则
	case CMD_DELETE_NUM://删除规则--指定规则号
	case CMD_CHECK://检查规则是否存在
	case CMD_REPLACE://替换规则
	case CMD_INSERT://插入规则
	case CMD_FLUSH://清空规则
	case CMD_ZERO://清空规则计数
	case CMD_ZERO_NUM://对指定的规则号清空计数
	case CMD_LIST: //打印规则--L命令打印
	case CMD_LIST|CMD_ZERO: //打印后清空规则数目
	case CMD_LIST|CMD_ZERO_NUM: //指定打印后清空的规则号
	case CMD_LIST_RULES: //打印规则--S命令打印
	case CMD_LIST_RULES|CMD_ZERO: //打印后清空规则数目
	case CMD_LIST_RULES|CMD_ZERO_NUM: //指定打印后清空的规则号
	case CMD_NEW_CHAIN://添加链
	case CMD_DELETE_CHAIN://删除链
	case CMD_RENAME_CHAIN://重命名链
	case CMD_SET_POLICY://设置默认策略
	default:
		/* We should never reach this... */
		exit_tryhelp(2);
	}
```
append_entry()函数用于添加规则
append_entry功能为添加规则到struct xtc_handle结构中。
```
iptables/iptables.c
static int
append_entry(const xt_chainlabel chain, //操作的链表名称
	     struct ipt_entry *fw,  //保存规则的结构体
	     unsigned int nsaddrs,  //源地址的数目
	     const struct in_addr saddrs[], //源地址
	     const struct in_addr smasks[], //源地址掩码
	     unsigned int ndaddrs,  //目的地址的数目
	     const struct in_addr daddrs[], //目的地址
	     const struct in_addr dmasks[], //目的地址掩码
	     int verbose,   //是否打印详情
	     struct xtc_handle *handle) //保存所有表信息的结构体
{
	unsigned int i, j;
	int ret = 1;

	for (i = 0; i < nsaddrs; i++) { //保存源地址
		fw->ip.src.s_addr = saddrs[i].s_addr;
		fw->ip.smsk.s_addr = smasks[i].s_addr;
		for (j = 0; j < ndaddrs; j++) { //保存目的地址
			fw->ip.dst.s_addr = daddrs[j].s_addr;
			fw->ip.dmsk.s_addr = dmasks[j].s_addr;
			if (verbose)    //打印详细信息
				print_firewall_line(fw, handle);
			ret &= iptc_append_entry(chain, fw, handle);//
		}
	}

	return ret;
}
````
对每一组源地址和目的地址调用iptc_append_entry将规则添加到链中
```
libiptc/libip4tc.c
#define TC_APPEND_ENTRY		iptc_append_entry
```
```
libiptc/libiptc.c
/* Append entry `fw' to chain `chain'.  Equivalent to insert with
   rulenum = length of chain. */
int
TC_APPEND_ENTRY(const IPT_CHAINLABEL chain,
		const STRUCT_ENTRY *e,
		struct xtc_handle *handle)
{
	struct chain_head *c;
	struct rule_head *r;
	if (!(c = iptcc_find_label(chain, handle))) { //根据名字查找链
		DEBUGP("unable to find chain `%s'\n", chain);
		errno = ENOENT;
		return 0;
	}

	if (!(r = iptcc_alloc_rule(c, e->next_offset))) { //为规则分配空间
		DEBUGP("unable to allocate rule for chain `%s'\n", chain);
		errno = ENOMEM;
		return 0;
	}

	memcpy(r->entry, e, e->next_offset); //拷贝规则信息
	r->counter_map.maptype = COUNTER_MAP_SET;

	if (!iptcc_map_target(handle, r)) {
		DEBUGP("unable to map target of rule for chain `%s'\n", chain);
		free(r);
		return 0;
	}

	list_add_tail(&r->list, &c->rules); //在规则表的尾部添加规则
	c->num_rules++; //规则数目增加

	set_changed(handle); //标记handle已经被修改

	return 1;
}
```
#### 5. iptc_commit
iptc_commit功能为将修改后的struct xtc_handle重组并将其发送到内核，还可以修改规则和链表的计数值。
```
libiptc/libip4tc.c
#define TC_COMMIT		iptc_commit
```
```
libiptc/libiptc.c
int
TC_COMMIT(struct xtc_handle *handle)
{
	/* Replace, then map back the counters. */
	STRUCT_REPLACE *repl;
	STRUCT_COUNTERS_INFO *newcounters;
	struct chain_head *c;
	int ret;
	size_t counterlen;
	int new_number;
	unsigned int new_size;

	/* Don't commit if nothing changed. */
	if (!handle->changed) //如果没有修改就不和内核交互
		goto finished;
    //统计修改后规则的数目以及占用空间的大小
	new_number = iptcc_compile_table_prep(handle, &new_size);
	if (new_number < 0) {
		errno = ENOMEM;
		goto out_zero;
	}
    //分配空间保存所有规则信息
	repl = malloc(sizeof(*repl) + new_size);
	if (!repl) {
		errno = ENOMEM;
		goto out_zero;
	}
	memset(repl, 0, sizeof(*repl) + new_size);

	counterlen = sizeof(STRUCT_COUNTERS_INFO)//修改后的计数个数
			+ sizeof(STRUCT_COUNTERS) * new_number;

	/* These are the old counters we will get from kernel */
	repl->counters = malloc(sizeof(STRUCT_COUNTERS)
				* handle->info.num_entries);
	if (!repl->counters) {
		errno = ENOMEM;
		goto out_free_repl;
	}
	/* These are the counters we're going to put back, later. */
	newcounters = malloc(counterlen);
	if (!newcounters) {
		errno = ENOMEM;
		goto out_free_repl_counters;
	}
	memset(newcounters, 0, counterlen);
    //初始化返回数据的信息有表的名称等
	strcpy(repl->name, handle->info.name);
	repl->num_entries = new_number;
	repl->size = new_size;

	repl->num_counters = handle->info.num_entries;
	repl->valid_hooks  = handle->info.valid_hooks;

    //将struct xtc_handle结构体内容拷贝到repl中发送给内核
	ret = iptcc_compile_table(handle, repl);
	if (ret < 0) {
		errno = ret;
		goto out_free_newcounters;
	}
    //通过setsockopt将repl数据返回给内核
	ret = setsockopt(handle->sockfd, TC_IPPROTO, SO_SET_REPLACE, repl,
			 sizeof(*repl) + repl->size);
	if (ret < 0)
		goto out_free_newcounters;

	/* Put counters back. */ //将计数值写回
	strcpy(newcounters->name, handle->info.name);
	newcounters->num_counters = new_number;//计数值个数

	list_for_each_entry(c, &handle->chains, list) {
		struct rule_head *r;

		/* Builtin chains have their own counters */
		if (iptcc_is_builtin(c)) {
			DEBUGP("counter for chain-index %u: ", c->foot_index);
			switch(c->counter_map.maptype) {
            //根据计数值map填充链计数值
			}
		}

		list_for_each_entry(r, &c->rules, list) {
			DEBUGP("counter for index %u: ", r->index);
            //根据规则计数值map填充规则计数值
		}
	}
    //通过setsockopt将计数值发送到内核
	ret = setsockopt(handle->sockfd, TC_IPPROTO, SO_SET_ADD_COUNTERS,
			 newcounters, counterlen);
}
```
### 四、内核接收部分
Iptables应用层和内核进行通信的方式为通过套接字。
```
net/ipv4/netfilter/ip_tables.c ip_tables_init()
	/* Register setsockopt */
	ret = nf_register_sockopt(&ipt_sockopts); //注册sockopt
```
其中ipt_sockopts为struct nf_sockopt_ops结构体。
```
static struct nf_sockopt_ops ipt_sockopts = {
	.pf		= PF_INET,
	.set_optmin	= IPT_BASE_CTL, //SET操作最小可操作的参数值
	.set_optmax	= IPT_SO_SET_MAX+1, //SET最大可操作的参数值
	.set		= do_ipt_set_ctl, //SET操作的处理函数
#ifdef CONFIG_COMPAT
	.compat_set	= compat_do_ipt_set_ctl,
#endif
	.get_optmin	= IPT_BASE_CTL, //GET操作最小可操作的参数值
	.get_optmax	= IPT_SO_GET_MAX+1, //GET最大可操作的参数值
	.get		= do_ipt_get_ctl, //GET操作的处理函数
#ifdef CONFIG_COMPAT
	.compat_get	= compat_do_ipt_get_ctl,
#endif
	.owner		= THIS_MODULE,
};
```
GET和SET可操作参数的宏如下：
```
#define IPT_BASE_CTL		64

#define IPT_SO_SET_REPLACE	(IPT_BASE_CTL) //将新的iptables命令写回
#define IPT_SO_SET_ADD_COUNTERS	(IPT_BASE_CTL + 1) //设置包数据
#define IPT_SO_SET_MAX		IPT_SO_SET_ADD_COUNTERS

#define IPT_SO_GET_INFO			(IPT_BASE_CTL) //返回内核保存的iptables表信息
#define IPT_SO_GET_ENTRIES		(IPT_BASE_CTL + 1)//返回所有保存的规则
#define IPT_SO_GET_REVISION_MATCH	(IPT_BASE_CTL + 2)
#define IPT_SO_GET_REVISION_TARGET	(IPT_BASE_CTL + 3)
#define IPT_SO_GET_MAX			IPT_SO_GET_REVISION_TARGET
```
get操作函数定义
```
compat_do_ipt_get_ctl(struct sock *sk, int cmd, void __user *user, int *len)
{
    ...
	switch (cmd) {
	case IPT_SO_GET_INFO:
		ret = get_info(sock_net(sk), user, len, 1);
		break;
	case IPT_SO_GET_ENTRIES:
		ret = compat_get_entries(sock_net(sk), user, len);
		break;
	default:
		ret = do_ipt_get_ctl(sk, cmd, user, len);
	}
    ...
}
```
get_info返回
```
static int get_info(struct net *net, void __user *user,
                    const int *len, int compat)
{
	char name[XT_TABLE_MAXNAMELEN];
	struct xt_table *t;
	int ret;
    ...
	if (copy_from_user(name, user, sizeof(name)) != 0) //读取表的名字
		return -EFAULT;

	name[XT_TABLE_MAXNAMELEN-1] = '\0';
	t = try_then_request_module(xt_find_table_lock(net, AF_INET, name),
				    "iptable_%s", name); //用户层加载对应的内核模块iptable_filter
	if (!IS_ERR_OR_NULL(t)) {
		struct ipt_getinfo info;
		const struct xt_table_info *private = t->private;
		memset(&info, 0, sizeof(info));
		info.valid_hooks = t->valid_hooks;
		memcpy(info.hook_entry, private->hook_entry,
		       sizeof(info.hook_entry));
		memcpy(info.underflow, private->underflow,
		       sizeof(info.underflow));
		info.num_entries = private->number;
		info.size = private->size;
		strcpy(info.name, name);

		if (copy_to_user(user, &info, *len) != 0)
			ret = -EFAULT;
		else
			ret = 0;
        ...
	} else
		ret = t ? PTR_ERR(t) : -ENOENT;
	return ret;
}

### 五、参考文献
```
iptables 源码分析
http://www.chinaunix.net/old_jh/4/663849.html
(十一)洞悉linux下的Netfilter&iptables：iptables命令行工具源码解析【上】
http://blog.chinaunix.net/uid-23069658-id-3222686.html
(十二)洞悉linux下的Netfilter&iptables：iptables命令行工具源码解析【下】
http://blog.chinaunix.net/uid-23069658-id-3223404.html
(十四)洞悉linux下的Netfilter&iptables：开发一个match模块【实战】
http://blog.chinaunix.net/uid-23069658-id-3230608.html
iptables 分析(一) 
http://blog.chinaunix.net/uid-24207747-id-2622900.html
```

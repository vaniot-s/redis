#ifndef __CLUSTER_H
#define __CLUSTER_H

/*-----------------------------------------------------------------------------
 * Redis cluster data structures, defines, exported API.
 *----------------------------------------------------------------------------*/

#define CLUSTER_SLOTS 16384
#define CLUSTER_OK 0          /* Everything looks ok */
#define CLUSTER_FAIL 1        /* The cluster can't work */
#define CLUSTER_NAMELEN 40    /* sha1 hex length */
#define CLUSTER_PORT_INCR 10000 /* Cluster port = baseport + PORT_INCR */

/* The following defines are amount of time, sometimes expressed as
 * multiplicators of the node timeout value (when ending with MULT). */
#define CLUSTER_FAIL_REPORT_VALIDITY_MULT 2 /* Fail report validity. */
#define CLUSTER_FAIL_UNDO_TIME_MULT 2 /* Undo fail if master is back. */
#define CLUSTER_FAIL_UNDO_TIME_ADD 10 /* Some additional time. */
#define CLUSTER_FAILOVER_DELAY 5 /* Seconds */
#define CLUSTER_MF_TIMEOUT 5000 /* Milliseconds to do a manual failover. */
#define CLUSTER_MF_PAUSE_MULT 2 /* Master pause manual failover mult. */
#define CLUSTER_SLAVE_MIGRATION_DELAY 5000 /* Delay for slave migration. */

/* Redirection errors returned by getNodeByQuery(). */
#define CLUSTER_REDIR_NONE 0          /* Node can serve the request. */
#define CLUSTER_REDIR_CROSS_SLOT 1    /* -CROSSSLOT request. */
#define CLUSTER_REDIR_UNSTABLE 2      /* -TRYAGAIN redirection required */
#define CLUSTER_REDIR_ASK 3           /* -ASK redirection required. */
#define CLUSTER_REDIR_MOVED 4         /* -MOVED redirection required. */
#define CLUSTER_REDIR_DOWN_STATE 5    /* -CLUSTERDOWN, global state. */
#define CLUSTER_REDIR_DOWN_UNBOUND 6  /* -CLUSTERDOWN, unbound slot. */
#define CLUSTER_REDIR_DOWN_RO_STATE 7 /* -CLUSTERDOWN, allow reads. */

struct clusterNode;

/* clusterLink encapsulates everything needed to talk with a remote node. */
// 保存链接节点所需要的有关信息
typedef struct clusterLink {
    // 创建链接的时间
    mstime_t ctime;             /* Link creation time */
    // TCP套接字描述符
    connection *conn;           /* Connection to remote node */
    // 输出缓冲区，保存等待发送给其他节点的消息
    sds sndbuf;                 /* Packet send buffer */
    // 输入缓冲区,保存从其他节点接收到的消息
    char *rcvbuf;               /* Packet reception buffer */
    size_t rcvbuf_len;          /* Used size of rcvbuf */
    size_t rcvbuf_alloc;        /* Allocated size of rcvbuf */
    // 与这个节点链接相关的节点，没有设为null
    struct clusterNode *node;   /* Node related to this link if any, or NULL */
} clusterLink;

/* Cluster node flags and macros. */
#define CLUSTER_NODE_MASTER 1     /* The node is a master */
#define CLUSTER_NODE_SLAVE 2      /* The node is a slave */
#define CLUSTER_NODE_PFAIL 4      /* Failure? Need acknowledge */
#define CLUSTER_NODE_FAIL 8       /* The node is believed to be malfunctioning */
#define CLUSTER_NODE_MYSELF 16    /* This node is myself */
#define CLUSTER_NODE_HANDSHAKE 32 /* We have still to exchange the first ping */
#define CLUSTER_NODE_NOADDR   64  /* We don't know the address of this node */
#define CLUSTER_NODE_MEET 128     /* Send a MEET message to this node */
#define CLUSTER_NODE_MIGRATE_TO 256 /* Master eligible for replica migration. */
#define CLUSTER_NODE_NOFAILOVER 512 /* Slave will not try to failover. */
#define CLUSTER_NODE_NULL_NAME "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"

#define nodeIsMaster(n) ((n)->flags & CLUSTER_NODE_MASTER)
#define nodeIsSlave(n) ((n)->flags & CLUSTER_NODE_SLAVE)
#define nodeInHandshake(n) ((n)->flags & CLUSTER_NODE_HANDSHAKE)
#define nodeHasAddr(n) (!((n)->flags & CLUSTER_NODE_NOADDR))
#define nodeWithoutAddr(n) ((n)->flags & CLUSTER_NODE_NOADDR)
#define nodeTimedOut(n) ((n)->flags & CLUSTER_NODE_PFAIL)
#define nodeFailed(n) ((n)->flags & CLUSTER_NODE_FAIL)
#define nodeCantFailover(n) ((n)->flags & CLUSTER_NODE_NOFAILOVER)

/* Reasons why a slave is not able to failover. */
#define CLUSTER_CANT_FAILOVER_NONE 0
#define CLUSTER_CANT_FAILOVER_DATA_AGE 1
#define CLUSTER_CANT_FAILOVER_WAITING_DELAY 2
#define CLUSTER_CANT_FAILOVER_EXPIRED 3
#define CLUSTER_CANT_FAILOVER_WAITING_VOTES 4
#define CLUSTER_CANT_FAILOVER_RELOG_PERIOD (60*5) /* seconds. */

/* clusterState todo_before_sleep flags. */
#define CLUSTER_TODO_HANDLE_FAILOVER (1<<0)
#define CLUSTER_TODO_UPDATE_STATE (1<<1)
#define CLUSTER_TODO_SAVE_CONFIG (1<<2)
#define CLUSTER_TODO_FSYNC_CONFIG (1<<3)
#define CLUSTER_TODO_HANDLE_MANUALFAILOVER (1<<4)

/* Message types.
 *
 * Note that the PING, PONG and MEET messages are actually the same exact
 * kind of packet. PONG is the reply to ping, in the exact format as a PING,
 * while MEET is a special PING that forces the receiver to add the sender
 * as a node (if it is not already in the list). */
#define CLUSTERMSG_TYPE_PING 0          /* Ping */
#define CLUSTERMSG_TYPE_PONG 1          /* Pong (reply to Ping) */
#define CLUSTERMSG_TYPE_MEET 2          /* Meet "let's join" message */
#define CLUSTERMSG_TYPE_FAIL 3          /* Mark node xxx as failing */
#define CLUSTERMSG_TYPE_PUBLISH 4       /* Pub/Sub Publish propagation */
#define CLUSTERMSG_TYPE_FAILOVER_AUTH_REQUEST 5 /* May I failover? */
#define CLUSTERMSG_TYPE_FAILOVER_AUTH_ACK 6     /* Yes, you have my vote */
#define CLUSTERMSG_TYPE_UPDATE 7        /* Another node slots configuration */
#define CLUSTERMSG_TYPE_MFSTART 8       /* Pause clients for manual failover */
#define CLUSTERMSG_TYPE_MODULE 9        /* Module cluster API message. */
#define CLUSTERMSG_TYPE_COUNT 10        /* Total number of message types. */

/* Flags that a module can set in order to prevent certain Redis Cluster
 * features to be enabled. Useful when implementing a different distributed
 * system on top of Redis Cluster message bus, using modules. */
#define CLUSTER_MODULE_FLAG_NONE 0
#define CLUSTER_MODULE_FLAG_NO_FAILOVER (1<<1)
#define CLUSTER_MODULE_FLAG_NO_REDIRECTION (1<<2)

/* This structure represent elements of node->fail_reports. */
typedef struct clusterNodeFailReport {
    // 报告目标节点已经下线的节点
    struct clusterNode *node;  /* Node reporting the failure condition. */
    // 最后一次从node节点收到下线报告的时间，程序使用这个时间戳检查下线报告是否过期
    mstime_t time;             /* Time of the last report from this node. */
} clusterNodeFailReport;

// 保存一个节点的当前状态
typedef struct clusterNode {
    // 创建节点的时间
    mstime_t ctime; /* Node object creation time. */
    // 节点的名字
    char name[CLUSTER_NAMELEN]; /* Node name, hex string, sha1-size */
    // 节点标识，使用各种不同的标识值记录节点的角色(主节点,从节点),以及节点目前所处的状态(上线，下线)
    int flags;      /* CLUSTER_NODE_... */
    // 节点当前配置纪元，用于实现故障转移
    uint64_t configEpoch; /* Last configEpoch observed for this node */
    // 二进制数组
    unsigned char slots[CLUSTER_SLOTS/8]; /* slots handled by this node */
    sds slots_info; /* Slots info represented by string. */
    int numslots;   /* Number of slots handled by this node */
    // 　正在复制这个主节点的从节点数量
    int numslaves;  /* Number of slave nodes, if this is a master */
    // 数组，每个数组项指向一个正在复制这个主节点的从节点的clusterNode结构
    struct clusterNode **slaves; /* pointers to slave nodes */
    // 当前节点是从节点，指向主节点
    struct clusterNode *slaveof; /* pointer to the master node. Note that it
                                    may be NULL even if the node is a slave
                                    if we don't have the master node in our
                                    tables. */
    mstime_t ping_sent;      /* Unix time we sent latest ping */
    mstime_t pong_received;  /* Unix time we received the pong */
    mstime_t data_received;  /* Unix time we received any data */
    mstime_t fail_time;      /* Unix time when FAIL flag was set */
    mstime_t voted_time;     /* Last time we voted for a slave of this master */
    mstime_t repl_offset_time;  /* Unix time we received offset for this node */
    mstime_t orphaned_time;     /* Starting time of orphaned master condition */
    long long repl_offset;      /* Last known repl offset for this node. */
    // 节点的IP地址
    char ip[NET_IP_STR_LEN];  /* Latest known IP address of this node */
    // 节点的端口号
    int port;                   /* Latest known clients port of this node */
    int cport;                  /* Latest known cluster port of this node. */
    // 保存链接节点所需要的有关信息
    clusterLink *link;          /* TCP/IP link with this node */
    //　链表，记录所有其他节点对于该节点的下线报告
    list *fail_reports;         /* List of nodes signaling this as failing */
} clusterNode;

// 当前节点的视角下，集群所处的状态
typedef struct clusterState {
    // 指向当前节点的指针
    clusterNode *myself;  /* This node */
    // 集群当前的配置纪元，用于实现故障转移
    uint64_t currentEpoch;
    // 集群当前的状态:在线还是下线
    int state;            /* CLUSTER_OK, CLUSTER_FAIL, ... */
    // 集群中至少处理着一个槽的节点的数量
    int size;             /* Num of master nodes with at least one slot */
    // 集群节点名单(包括myself节点),字典的键为节点的名字,字典的值为节点对应的clusterNode结构
    dict *nodes;          /* Hash table of name -> clusterNode structures */
    dict *nodes_black_list; /* Nodes we don't re-add for a few seconds. */
    // 当前节点正在迁移至其他节点的槽
    clusterNode *migrating_slots_to[CLUSTER_SLOTS];
    //　记录当前节点正在从其他节点导入的槽
    clusterNode *importing_slots_from[CLUSTER_SLOTS];
    // 记录集群中所有１６３８４指派信息，每一项指向clusterNode结构的指针
    clusterNode *slots[CLUSTER_SLOTS];
    uint64_t slots_keys_count[CLUSTER_SLOTS];
    // 保存槽和键之间的关系
    rax *slots_to_keys;
    /* The following fields are used to take the slave state on elections. */
    mstime_t failover_auth_time; /* Time of previous or next election. */
    int failover_auth_count;    /* Number of votes received so far. */
    int failover_auth_sent;     /* True if we already asked for votes. */
    int failover_auth_rank;     /* This slave rank for current auth request. */
    uint64_t failover_auth_epoch; /* Epoch of the current election. */
    int cant_failover_reason;   /* Why a slave is currently not able to
                                   failover. See the CANT_FAILOVER_* macros. */
    /* Manual failover state in common. */
    mstime_t mf_end;            /* Manual failover time limit (ms unixtime).
                                   It is zero if there is no MF in progress. */
    /* Manual failover state of master. */
    clusterNode *mf_slave;      /* Slave performing the manual failover. */
    /* Manual failover state of slave. */
    long long mf_master_offset; /* Master offset the slave needs to start MF
                                   or zero if still not received. */
    int mf_can_start;           /* If non-zero signal that the manual failover
                                   can start requesting masters vote. */
    /* The following fields are used by masters to take state on elections. */
    uint64_t lastVoteEpoch;     /* Epoch of the last vote granted. */
    int todo_before_sleep; /* Things to do in clusterBeforeSleep(). */
    /* Messages received and sent by type. */
    long long stats_bus_messages_sent[CLUSTERMSG_TYPE_COUNT];
    long long stats_bus_messages_received[CLUSTERMSG_TYPE_COUNT];
    long long stats_pfail_nodes;    /* Number of nodes in PFAIL status,
                                       excluding nodes without address. */
} clusterState;

/* Redis cluster messages header */

/* Initially we don't know our "name", but we'll find it once we connect
 * to the first node, using the getsockname() function. Then we'll use this
 * address for all the next messages. */
// 记录被选中的节点的名字
typedef struct {
    // 节点名字
    char nodename[CLUSTER_NAMELEN];
    // 最后一次向该节点发送PING消息的时间错
    uint32_t ping_sent;
    // 最后一次从该节点收到pong消息的时间戳
    uint32_t pong_received;
    // 节点的IP地址
    char ip[NET_IP_STR_LEN];  /* IP address last time it was seen */
    // 节点的端口号
    uint16_t port;              /* base port last time it was seen */
    uint16_t cport;             /* cluster port last time it was seen */
    // 节点的标识值
    uint16_t flags;             /* node->flags copy */
    uint32_t notused1;
} clusterMsgDataGossip;

//　标记已经下线的主节点
typedef struct {
    char nodename[CLUSTER_NAMELEN];
} clusterMsgDataFail;

// 向集群中广播消息
typedef struct {
    uint32_t channel_len;
    uint32_t message_len;
    unsigned char bulk_data[8]; /* 8 bytes just as placeholder. */
} clusterMsgDataPublish;

typedef struct {
    uint64_t configEpoch; /* Config epoch of the specified instance. */
    char nodename[CLUSTER_NAMELEN]; /* Name of the slots owner. */
    unsigned char slots[CLUSTER_SLOTS/8]; /* Slots bitmap. */
} clusterMsgDataUpdate;

typedef struct {
    uint64_t module_id;     /* ID of the sender module. */
    uint32_t len;           /* ID of the sender module. */
    uint8_t type;           /* Type from 0 to 255. */
    unsigned char bulk_data[3]; /* 3 bytes just as placeholder. */
} clusterMsgModule;

union clusterMsgData {
    /* PING, MEET and PONG 消息正文*/
    struct {
        /* Array of N clusterMsgDataGossip structures */
        // 每条MEET,PING,PONG消息都包含两个clusterMsgDataGossip
        clusterMsgDataGossip gossip[1];
    } ping;

    /* FAIL */
    // FAIL消息正文
    struct {
        clusterMsgDataFail about;
    } fail;

    /* PUBLISH */
    // publish消息的正文
    struct {
        clusterMsgDataPublish msg;
    } publish;

    /* UPDATE */
    struct {
        clusterMsgDataUpdate nodecfg;
    } update;

    /* MODULE */
    struct {
        clusterMsgModule msg;
    } module;
};

#define CLUSTER_PROTO_VER 1 /* Cluster bus protocol version. */

//　消息头:　包含消息正文，记录消息发送者自身的信息
typedef struct {
    char sig[4];        /* Signature "RCmb" (Redis Cluster message bus). */
    // 消息的长度
    uint32_t totlen;    /* Total length of this message */
    //
    uint16_t ver;       /* Protocol version, currently set to 1. */
    // 发送者的端口号
    uint16_t port;      /* TCP base port number. */
    // 消息类型
    uint16_t type;      /* Message type */
    // 消息正文包含的节点信息数量，只在发送MEET,PING,PONG这三种Gossip协议消息时使用
    uint16_t count;     /* Only used for some kind of messages. */
    // 发送者所处的配置纪元
    uint64_t currentEpoch;  /* The epoch accordingly to the sending node. */
    // 如果发送者是一个主节点，记录的是发送者的配置纪元
    // 发送者是一个从节点，记录发送者正在复制的住节点的配置纪元
    uint64_t configEpoch;   /* The config epoch if it's a master, or the last
                               epoch advertised by its master if it is a
                               slave. */
    uint64_t offset;    /* Master replication offset if node is a master or
                           processed replication offset if node is a slave. */
    // 发送者的名字
    char sender[CLUSTER_NAMELEN]; /* Name of the sender node */
    // 发送者目前的的槽指派信息
    unsigned char myslots[CLUSTER_SLOTS/8];
    // 如果发送者是一个从节点,这里记录的是发送者正在复制的主节点的名字
    // 发送这是一个主节点，这里记录的是REDIS_NODE_NULL_NAME
    char slaveof[CLUSTER_NAMELEN];
    char myip[NET_IP_STR_LEN];    /* Sender IP, if not all zeroed. */
    char notused1[34];  /* 34 bytes reserved for future usage. */
    uint16_t cport;      /* Sender TCP cluster bus port */
    // 发送者标识值
    uint16_t flags;      /* Sender node flags */
    // 发送者所处集群的状态
    unsigned char state; /* Cluster state from the POV of the sender */
    unsigned char mflags[3]; /* Message flags: CLUSTERMSG_FLAG[012]_... */
    // 消息的正文
    union clusterMsgData data;
} clusterMsg;

#define CLUSTERMSG_MIN_LEN (sizeof(clusterMsg)-sizeof(union clusterMsgData))

/* Message flags better specify the packet content or are used to
 * provide some information about the node state. */
#define CLUSTERMSG_FLAG0_PAUSED (1<<0) /* Master paused for manual failover. */
#define CLUSTERMSG_FLAG0_FORCEACK (1<<1) /* Give ACK to AUTH_REQUEST even if
                                            master is up. */

/* ---------------------- API exported outside cluster.c -------------------- */
clusterNode *getNodeByQuery(client *c, struct redisCommand *cmd, robj **argv, int argc, int *hashslot, int *ask);
int clusterRedirectBlockedClientIfNeeded(client *c);
void clusterRedirectClient(client *c, clusterNode *n, int hashslot, int error_code);
unsigned long getClusterConnectionsCount(void);

#endif /* __CLUSTER_H */

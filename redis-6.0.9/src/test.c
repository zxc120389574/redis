#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdarg.h>

#define LL_RAW (1<<10)

struct RedisServer {
    char *logfile;
    int verbosity;                  /* Loglevel in redis.conf */
    time_t timezone;            /* Cached timezone. As set by tzset(). */
    int daylight_active;        /* Currently in daylight saving time. */
    int sentinel_mode;          /* True if this instance is a Sentinel. */
    pid_t pid;                  /* Main process pid. */
    char *masterhost;               /* Hostname of master */
    int syslog_enabled;             /* Is syslog enabled? */
};

struct RedisServer server;

void initServerObj(){
    tzset(); /* Now 'timezome' global is populated. */
    time_t t = time(NULL);
    struct tm *aux = localtime(&t);

    server.logfile = "my_log.txt";
    server.verbosity = 0;
    server.timezone = timezone;
    server.daylight_active = aux->tm_isdst;
    server.sentinel_mode = 0;
    server.pid = 123;
    server.masterhost = "hostname";
    server.syslog_enabled = 1;
}

static int is_leap_year(time_t year) {
    if (year % 4) return 0;         /* A year not divisible by 4 is not leap. */
    else if (year % 100) return 1;  /* If div by 4 and not 100 is surely leap. */
    else if (year % 400) return 0;  /* If div by 100 *and* not by 400 is not leap. */
    else return 1;                  /* If div by 100 and 400 is leap. */
}

void nolocks_localtime(struct tm *tmp, time_t t, time_t tz, int dst) { // localtime函数有死锁的风险，所以作者自己写了一个非阻塞的localtime函数。
    const time_t secs_min = 60;
    const time_t secs_hour = 3600;
    const time_t secs_day = 3600*24;

    t -= tz;                            /* Adjust for timezone. */
    t += 3600*dst;                      /* Adjust for daylight time. */
    time_t days = t / secs_day;         /* Days passed since epoch. */
    time_t seconds = t % secs_day;      /* Remaining seconds. */

    tmp->tm_isdst = dst;
    tmp->tm_hour = seconds / secs_hour;
    tmp->tm_min = (seconds % secs_hour) / secs_min;
    tmp->tm_sec = (seconds % secs_hour) % secs_min;

    /* 1/1/1970 was a Thursday, that is, day 4 from the POV of the tm structure
     * where sunday = 0, so to calculate the day of the week we have to add 4
     * and take the modulo by 7. */
    tmp->tm_wday = (days+4)%7;

    /* Calculate the current year. */
    tmp->tm_year = 1970;
    while(1) {
        /* Leap years have one day more. */
        time_t days_this_year = 365 + is_leap_year(tmp->tm_year);
        if (days_this_year > days) break;
        days -= days_this_year;
        tmp->tm_year++;
    }
    tmp->tm_yday = days;  /* Number of day of the current year. */

    /* We need to calculate in which month and day of the month we are. To do
     * so we need to skip days according to how many days there are in each
     * month, and adjust for the leap year that has one more day in February. */
    int mdays[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    mdays[1] += is_leap_year(tmp->tm_year);

    tmp->tm_mon = 0;
    while(days >= mdays[tmp->tm_mon]) {
        days -= mdays[tmp->tm_mon];
        tmp->tm_mon++;
    }

    tmp->tm_mday = days+1;  /* Add 1 since our 'days' is zero-based. */
    tmp->tm_year -= 1900;   /* Surprisingly tm_year is year-1900. */
}

#ifdef LOCALTIME_TEST_MAIN
#include <stdio.h>

int main(void) {
    /* Obtain timezone and daylight info. */
    tzset(); /* Now 'timezome' global is populated. */
    time_t t = time(NULL);
    struct tm *aux = localtime(&t);
    int daylight_active = aux->tm_isdst;

    struct tm tm;
    char buf[1024];

    nolocks_localtime(&tm,t,timezone,daylight_active);
    strftime(buf,sizeof(buf),"%d %b %H:%M:%S",&tm);
    printf("[timezone: %d, dl: %d] %s\n", (int)timezone, (int)daylight_active, buf);
}
#endif

void serverLogRaw(int level, const char *msg) {
    const int syslogLevelMap[] = { LOG_DEBUG, LOG_INFO, LOG_NOTICE, LOG_WARNING };
    const char *c = ".-*#";
    FILE *fp;
    char buf[64];
    int rawmode = (level & LL_RAW);
    int log_to_stdout = server.logfile[0] == '\0';

    level &= 0xff; /* clear flags */
    if (level < server.verbosity) return;

    fp = log_to_stdout ? stdout : fopen(server.logfile,"a");
    if (!fp) return;

    if (rawmode) {
        fprintf(fp,"%s",msg);
    } else {
        int off;
        struct timeval tv;
        int role_char;
        pid_t pid = getpid();

        gettimeofday(&tv,NULL);
        struct tm tm;
        nolocks_localtime(&tm,tv.tv_sec,server.timezone,server.daylight_active);
        off = strftime(buf,sizeof(buf),"%d %b %Y %H:%M:%S.",&tm);
        snprintf(buf+off,sizeof(buf)-off,"%03d",(int)tv.tv_usec/1000);
        
        if (server.sentinel_mode) {
            role_char = 'X'; /* Sentinel. */
        } else if (pid != server.pid) {
            role_char = 'C'; /* RDB / AOF writing child. */
        } else {
            role_char = (server.masterhost ? 'S':'M'); /* Slave or Master. */
        }
        fprintf(fp,"%d:%c %s %c %s\n",
            (int)getpid(),role_char, buf,c[level],msg);
    }
    fflush(fp);

    if (!log_to_stdout) fclose(fp);
    if (server.syslog_enabled) syslog(syslogLevelMap[level], "%s", msg);
}


void serverLog(int level, const char *fmt, ...) {
    va_list ap;
    #define LOG_MAX_LEN 100
    char msg[LOG_MAX_LEN];

    if ((level&0xff) < server.verbosity) return;

    va_start(ap, fmt); // fmt初始化ap。fmt不能是string类型，因为string结尾有\0，所以最后只会输出第一个string。
    vsnprintf(msg, sizeof(msg), fmt, ap);
    printf("%s\n", msg);
    va_end(ap);

    serverLogRaw(level,msg);
}



int main(){
    initServerObj();
    //serverLogRaw(4, "zhangxuchang, hehe, hehe");
    char s1[3] = {'h', 'e', 'l'};
    char s2[3] = {'z', 'x', 'c'};
    char s3[3] = {'q', 'w', 'e'};
    serverLog(4, s1, s2, s3);

    return 0;
}
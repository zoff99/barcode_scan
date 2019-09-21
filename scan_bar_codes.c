/*
 * Copyright © 2019 Zoff <zoff@zoff.cc>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * originally from:
 * 
 *    https://stackoverflow.com/questions/55546721/how-to-reliably-read-usb-barcode-scanner-in-embedded-headless-linux
 *    https://stackoverflow.com/questions/7668872/need-to-intercept-hid-keyboard-events-and-then-block-them
 */

/*
 * compile with:
 * 
 *    gcc -O0 -Wall -Wextra scan_bar_codes.c -fsanitize=address -fno-omit-frame-pointer -lasan -o scan_bar_codes
 * 
 * HINT: !! add current user to group "input" !!
 */

#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <linux/input.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>


// ----------- version -----------
// ----------- version -----------
#define VERSION_MAJOR 0
#define VERSION_MINOR 99
#define VERSION_PATCH 0
static const char global_version_string[] = "0.99.0";
// ----------- version -----------
// ----------- version -----------

// ------ set the correct input device for the barcode scanner here --------------------------
// ------ set the correct input device for the barcode scanner here --------------------------
char scanner_devname[] = "/dev/input/by-id/usb-Newland_Auto-ID_NLS_IOTC_PRDs_HID_KBW_EX318458-event-kbd";
// ------ set the correct input device for the barcode scanner here --------------------------
// ------ set the correct input device for the barcode scanner here --------------------------


char ttab[] = {
     0,  27, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b',  /* Backspace */
  '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']','\n',        /* Enter key */
     0, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';','\'', '`',   0,        /* Left shift */
  '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/',   0,                  /* Right shift */
  '*',
    0,  /* Alt */
  ' ',  /* Space bar */
    0,  /* Caps lock */
    0,  /* 59 - F1 key ... > */
    0,   0,   0,   0,   0,   0,   0,   0,
    0,  /* < ... F10 */
    0,  /* 69 - Num lock*/
    0,  /* Scroll Lock */
    0,  /* Home key */
    0,  /* Up Arrow */
    0,  /* Page Up */
  '-',
    0,  /* Left Arrow */
    0,
    0,  /* Right Arrow */
  '+',
    0,  /* 79 - End key*/
    0,  /* Down Arrow */
    0,  /* Page Down */
    0,  /* Insert Key */
    0,  /* Delete Key */
    0,   0,   0,
    0,  /* F11 Key */
    0,  /* F12 Key */
    0,  /* All other keys are undefined */
};

char ntab[] = {
    0,  27, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b',   /* Backspace */
 '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']','\n',         /* Enter key */
    0, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';','\'', '`',   0,         /* Left shift */
 '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/',   0,                   /* Right shift */
  '*',
    0,  /* Alt */
  ' ',  /* Space bar */
    0,  /* Caps lock */
    0,  /* 59 - F1 key ... > */
    0,   0,   0,   0,   0,   0,   0,   0,
    0,  /* < ... F10 */
    0,  /* 69 - Num lock*/
    0,  /* Scroll Lock */
    0,  /* Home key */
    0,  /* Up Arrow */
    0,  /* Page Up */
  '-',
    0,  /* Left Arrow */
    0,
    0,  /* Right Arrow */
  '+',
    0,  /* 79 - End key*/
    0,  /* Down Arrow */
    0,  /* Page Down */
    0,  /* Insert Key */
    0,  /* Delete Key */
    0,   0,   0,
    0,  /* F11 Key */
    0,  /* F12 Key */
    0,  /* All other keys are undefined */
};

char stab[] = {
    0,  27, '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', 0,      /* Backspace */
    0, 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}',   0,         /* Enter key */
    0, 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"',   0,'\n',         /* Left shift */
    0, 'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?',   0,                   /* Right shift */
  '*',
    0,  /* Alt */
  ' ',  /* Space bar */
    0,  /* Caps lock */
    0,  /* 59 - F1 key ... > */
    0,   0,   0,   0,   0,   0,   0,   0,
    0,  /* < ... F10 */
    0,  /* 69 - Num lock*/
    0,  /* Scroll Lock */
    0,  /* Home key */
    0,  /* Up Arrow */
    0,  /* Page Up */
  '-',
    0,  /* Left Arrow */
    0,
    0,  /* Right Arrow */
  '+',
    0,  /* 79 - End key*/
    0,  /* Down Arrow */
    0,  /* Page Down */
    0,  /* Insert Key */
    0,  /* Delete Key */
    0,   0,   0,
    0,  /* F11 Key */
    0,  /* F12 Key */
    0,  /* All other keys are undefined */
};

#define CLEAR(x) memset(&(x), 0, sizeof(x))
#define CLEAR2(x, y) memset(x, 0, y)

int device_fd = -1;
const char *db_directory = "./db/";
const char *shell_cmd__onstart = "./on_start.sh 2> /dev/null";
const char *shell_cmd__onend = "./on_end.sh 2> /dev/null";
const char *shell_cmd__onerror = "./on_error.sh 2> /dev/null";
FILE *logfile = NULL;
#define CURRENT_LOG_LEVEL 9 // 0 -> error, 1 -> warn, 2 -> info, 9 -> debug
#define DOUBLE_SCAN_INTERVAL_MS 710

void usleep_usec(uint64_t usec)
{
    struct timespec ts;
    ts.tv_sec = usec / 1000000;
    ts.tv_nsec = (usec % 1000000) * 1000;
    nanosleep(&ts, NULL);
}

#define sleep_ms(x) usleep_usec(1000*x)

void open_logfile()
{
    logfile = stderr;
    setvbuf(logfile, NULL, _IONBF, 0);
}

void close_logfile()
{
    // dummy, nothing to close
}

void dbg(int level, const char *fmt, ...)
{
    char *level_and_format = NULL;
    char *fmt_copy = NULL;

    if (fmt == NULL)
    {
        return;
    }

    if (strlen(fmt) < 1)
    {
        return;
    }

    if (!logfile)
    {
        return;
    }

    if ((level < 0) || (level > 9))
    {
        level = 0;
    }

    level_and_format = calloc(1, strlen(fmt) + 3 + 1);

    if (!level_and_format)
    {
        return;
    }

    fmt_copy = level_and_format + 2;
    strcpy(fmt_copy, fmt);
    level_and_format[1] = ':';

    if (level == 0)
    {
        level_and_format[0] = 'E';
    }
    else if (level == 1)
    {
        level_and_format[0] = 'W';
    }
    else if (level == 2)
    {
        level_and_format[0] = 'I';
    }
    else
    {
        level_and_format[0] = 'D';
    }

    level_and_format[(strlen(fmt) + 2)] = '\0'; // '\0' or '\n'
    level_and_format[(strlen(fmt) + 3)] = '\0';
    time_t t3 = time(NULL);
    struct tm tm3 = *localtime(&t3);
    char *level_and_format_2 = calloc(1, strlen(level_and_format) + 5 + 3 + 3 + 1 + 3 + 3 + 3 + 1);
    level_and_format_2[0] = '\0';
    snprintf(level_and_format_2, (strlen(level_and_format) + 5 + 3 + 3 + 1 + 3 + 3 + 3 + 1),
             "%04d-%02d-%02d %02d:%02d:%02d:%s",
             tm3.tm_year + 1900, tm3.tm_mon + 1, tm3.tm_mday,
             tm3.tm_hour, tm3.tm_min, tm3.tm_sec, level_and_format);

    if (level <= CURRENT_LOG_LEVEL)
    {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(logfile, level_and_format_2, ap);
        va_end(ap);
    }

    if (level_and_format)
    {
        free(level_and_format);
    }

    if (level_and_format_2)
    {
        free(level_and_format_2);
    }
}

static inline void __utimer_start(struct timeval *tm1)
{
    gettimeofday(tm1, NULL);
}

static inline unsigned long long __utimer_stop(struct timeval *tm1)
{
    struct timeval tm2;
    gettimeofday(&tm2, NULL);
    unsigned long long t = 1000 * (tm2.tv_sec - tm1->tv_sec) + (tm2.tv_usec - tm1->tv_usec) / 1000;
    return t;
}


// Adjust date by a number of hours +/-
void date_plus_hours(struct tm* date, int hours)
{
    const time_t ONE_HOUR = 60 * 60 ;

    // Seconds since start of epoch
    time_t date_seconds = mktime(date) + (hours * ONE_HOUR);

    // Update caller's date
    // Use localtime because mktime converts to UTC so may change date
    *date = *localtime(&date_seconds);
}

/* HINT: caller of this function needs to "free()" the returned bytes after use! */
char *get_date_in_format()
{
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

    if (tm.tm_hour < 4)
    {
        // HINT: if hour is between [00:00 and 03:59] then sub 4 hours to get that date of the previous day!
        date_plus_hours(&tm, -4);
    }

    const size_t date_format_length = 4 + 1 + 2 + 1 + 2; // "year"(4)"-"(1)"month"(2)"-"(1)"day"(2)
    char *ret = calloc(1, (date_format_length + 1)); // +1 for the terminating NULL byte

    int res = snprintf(ret, (date_format_length + 1), "%04d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);

    if (res < 0)
    {
        CLEAR2(ret, (date_format_length + 1));
        ret[0] = 'U';
        ret[1] = 'n';
        ret[2] = 'k';
        ret[3] = 'w';
        ret[4] = 'n';
        return ret;
    }
    else
    {
        return ret;
    }
}

bool file_exists(const char *path)
{
    struct stat s;
    return stat(path, &s) == 0;
}

uint32_t read_value_from_file(char *filename)
{
    uint32_t ret = 0;
    uint8_t *value_bytes = (uint8_t *)(&ret);

    if (!file_exists(filename))
    {
        return 0;
    }

    FILE *fp = fopen(filename, "rb");

    if (fp == NULL)
    {
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize < (long)(sizeof(uint32_t)))
    {
        fclose(fp);
        return 0;
    }

    uint8_t j;
    for (j=0;j<sizeof(uint32_t);j++)
    {
        value_bytes[j] = fgetc(fp);
    }
    
    fclose(fp);
    
    dbg(2, "read_value_from_file:%d\n", ret);
    
    return ret;
}

void write_value_to_file(char *filename, uint32_t value)
{
    uint8_t *value_bytes = (uint8_t *)(&value);

    FILE *fp = fopen(filename, "wb");
    // setvbuf(fp, NULL, _IONBF, 0);

    if (fp == NULL)
    {
        return;
    }

    dbg(2, "write_value_to_file:%d\n", value);

    
    uint8_t j;
    for (j=0;j<sizeof(uint32_t);j++)
    {
        fputc(value_bytes[j], fp);
    }

    fflush(fp);
    fclose(fp);
}

static void write_code_to_file(char *code)
{
    if (!code)
    {
        dbg(2, "code is NULL\n");
        return;
    }

    if (strlen(code) > 298)
    {
        dbg(2, "code too long\n");
        return;
    }

    if (strlen(code) < 1)
    {
        dbg(2, "code is empty string\n");
        return;
    }

    char *directory_name = get_date_in_format();

    if (directory_name)
    {
        // make the db directoy just in case it got deleted while the program is running
        mkdir(db_directory, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP);

        char filename[300];
        CLEAR(filename);
        snprintf(filename, 299, "%s/%s", db_directory, directory_name);

        // make the current directoy for this day, if it already exists it doesnt matter
        mkdir(filename, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP);

        CLEAR(filename);
        snprintf(filename, 299, "%s/%s/%s", db_directory, directory_name, code);

        uint32_t amount = read_value_from_file(filename);
        write_value_to_file(filename, amount + 1);
        
        free(directory_name);
    }
}

void on_start_scanner()
{
    char cmd_str[1000];
    CLEAR(cmd_str);
    snprintf(cmd_str, sizeof(cmd_str), "%s", shell_cmd__onstart);

    if (system(cmd_str)){};

    dbg(2, "on_start_scanner\n");
}

void on_end_scanner()
{
    close(device_fd);
    
    char cmd_str[1000];
    CLEAR(cmd_str);
    snprintf(cmd_str, sizeof(cmd_str), "%s", shell_cmd__onend);

    if (system(cmd_str)){};
    
    dbg(2, "on_end_scanner\n");
}

void on_error_scanner()
{
    char cmd_str[1000];
    CLEAR(cmd_str);
    snprintf(cmd_str, sizeof(cmd_str), "%s", shell_cmd__onerror);

    if (system(cmd_str)){};
    
    dbg(2, "on_error_scanner\n");
}

void make_db_directory()
{
    mkdir(db_directory, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP);
}

bool init_scanner_device()
{
    char name[1000] = "Unknown";
    int result = 0;

    ioctl(device_fd, EVIOCGNAME(sizeof(name)), name);
    dbg(2, "Reading From: %s (%s)\n", scanner_devname, name);
    dbg(2, "Getting exclusive access:\n");

    result = ioctl(device_fd, EVIOCGRAB, 1);
    dbg(2, "%s\n", (result == 0) ? "SUCCESS" : "FAILURE");
    dbg(2, "ScanBarCodes Version:%s\n", global_version_string);

    if (result == 0)
    {
        on_start_scanner();
        return true;
    }
    else
    {
        return false;
    }
}

void INThandler()
{
    on_end_scanner();
    close_logfile();
    exit(0);
}

int main() {

    open_logfile();
    on_error_scanner();
    make_db_directory();

    struct timeval tm_01;
    long long timspan_in_ms = 99999;
    struct input_event ev;
    int shift = 0;
    char *line = calloc(1, 300);
    char *p = line;
    ssize_t read_result = 0;
    int loop1 = 1;

    const int max_code_length = 299;
    int current_code_length = 0;

    CLEAR2(line, 300);
    signal(SIGINT, INThandler);

    char *last_scanned_code = calloc(1, 300);
    CLEAR2(last_scanned_code, 300);

    while (loop1 == 1)
    {
        device_fd = open(scanner_devname, O_RDONLY);
        if (device_fd == -1)
        {
            // Failed to open event device
            // try again in a while
            // dbg(2, "Failed to open event device\n");
            sleep_ms(300);
        }
        else
        {
            if (init_scanner_device() == true)
            {
                // ok, break the loop
                loop1 = 0;
            }
            else
            {
                // try again
            }
        }
    }

    __utimer_start(&tm_01);

    while (true)
    {
        read_result = read(device_fd, &ev, sizeof(ev));

        if (read_result != -1)
        {
            if (ev.type == 1)
            {
                if (ev.code == 42)
                {
                    shift = ev.value;
                }
                else if (ev.value)
                {
                    char *t = shift ? stab : ntab;
                    char ch = t[ev.code];

                    if (ch == '\n')
                    {
                        *p = '\0';
                        timspan_in_ms = __utimer_stop(&tm_01);
                        // dbg(2, "delta ms=%lld\n", (long long)timspan_in_ms);

                        if ((timspan_in_ms < DOUBLE_SCAN_INTERVAL_MS)
                            &&
                            (strcmp(line, last_scanned_code) == 0))
                        {
                            dbg(2, "same code 2 times in a short time, this must be a false double scan\n");
                        }
                        else
                        {
                            __utimer_start(&tm_01);
                            write_code_to_file(line);
                            // remember the last scanned code
                            CLEAR2(last_scanned_code, 300);
                            strcpy(last_scanned_code, line);
                        }

                        CLEAR2(line, 300);
                        current_code_length = 0;
                        p = line;
                    }
                    else
                    {
                        if ((ch != '/') && (ch != '.'))
                        {
                            if (current_code_length >= max_code_length)
                            {
                                // code will be truncated here
                                // scanned code is already longer than the allowed code length!!
                                dbg(1, "scanned code is already longer than the allowed code length\n");
                            }
                            else
                            {
                                *p++ = ch;
                                current_code_length++;
                            }
                        }
                    }
                }
            }
        }
        else
        {
            // dbg(1, "errno= fd=%d\n", (int)errno, (int)device_fd);
            on_error_scanner();
            loop1 = 1;
            while (loop1 == 1)
            {
                device_fd = open(scanner_devname, O_RDONLY);
                if (device_fd == -1)
                {
                    // Failed to open event device
                    // try again in a while
                    // dbg(2, "Failed to open event device\n");
                    sleep_ms(300);
                }
                else
                {
                    if (init_scanner_device() == true)
                    {
                        // ok, break the loop
                        loop1 = 0;
                    }
                    else
                    {
                        // try again
                    }
                }
            }
        }
    }
    
    on_end_scanner();
    close_logfile();
    exit(0);
}



// ServerChat.h: 标准系统包含文件的包含文件
// 或项目特定的包含文件。

#pragma once

#include <iostream>

// TODO: 在此处引用程序需要的其他标头。
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <algorithm>
#include <cstring>


void server_epoll();

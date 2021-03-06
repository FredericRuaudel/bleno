#include <errno.h>
#include <signal.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>

#define ATT_CID 4

int lastSignal = 0;

static void signalHandler(int signal) {
  lastSignal = signal;
}

void debug (const char* format,...)
{
    FILE* fd = fopen("/tmp/debugBTLE.log", "a+");
    if (fd != NULL)
    {
				fprintf(fd, "L2CAP - ");
        va_list args;
        va_start (args, format);
        vfprintf(fd,format,args);
        va_end (args);
        fclose (fd);
    }
}

int main(int argc, const char* argv[]) {

  int serverL2capSock;
  struct sockaddr_l2 sockAddr;
  socklen_t sockAddrLen;
  int result;
  bdaddr_t clientBdAddr;
  int clientL2capSock;
	int sock_flags;

  fd_set afds;
  fd_set rfds;
  struct timeval tv;

  char stdinBuf[256 * 2 + 1];
  char l2capSockBuf[256];
  int len;
  int i;
  struct bt_security btSecurity;
  socklen_t btSecurityLen;
  uint8_t securityLevel = 0;

  // setup signal handlers
  signal(SIGINT, signalHandler);
  signal(SIGKILL, signalHandler);
  signal(SIGHUP, signalHandler);

  prctl(PR_SET_PDEATHSIG, SIGINT);

  // create socket
  serverL2capSock = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);

	// set non blocking socket
	sock_flags = fcntl(serverL2capSock,F_GETFL, 0);
	fcntl (serverL2capSock, F_SETFL, sock_flags | O_NONBLOCK);

  // bind
  memset(&sockAddr, 0, sizeof(sockAddr));
  sockAddr.l2_family = AF_BLUETOOTH;
  sockAddr.l2_bdaddr = *BDADDR_ANY;
  sockAddr.l2_cid = htobs(ATT_CID);

  result = bind(serverL2capSock, (struct sockaddr*)&sockAddr, sizeof(sockAddr));

	debug ("bind %s\n", (result == -1) ? strerror(errno) : "success");
  printf("bind %s\n", (result == -1) ? strerror(errno) : "success");

  result = listen(serverL2capSock, 1);

  debug("listen %s\n", (result == -1) ? strerror(errno) : "success");
  printf("listen %s\n", (result == -1) ? strerror(errno) : "success");

  while (result != -1) {
    FD_ZERO(&afds);
    FD_SET(serverL2capSock, &afds);

    tv.tv_sec = 1;
    tv.tv_usec = 0;

		debug("waiting connection from client...\n");
    result = select(serverL2capSock + 1, &afds, NULL, NULL, &tv);

    if (-1 == result) {
      if (SIGINT == lastSignal || SIGKILL == lastSignal) {
				debug("done\n");
        break;
      }
    } else if (result && FD_ISSET(serverL2capSock, &afds)) {
      sockAddrLen = sizeof(sockAddr);
      clientL2capSock = accept(serverL2capSock, (struct sockaddr *)&sockAddr, &sockAddrLen);
			

			// set non blocking socket      
			sock_flags = fcntl(clientL2capSock,F_GETFL, 0);
			fcntl (clientL2capSock, F_SETFL, sock_flags | O_NONBLOCK);

      baswap(&clientBdAddr, &sockAddr.l2_bdaddr);
      printf("accept %s\n", batostr(&clientBdAddr));
      debug("accept from %s\n", batostr(&clientBdAddr));

      while(1) {
        FD_ZERO(&rfds);
        FD_SET(0, &rfds);
        FD_SET(clientL2capSock, &rfds);

        tv.tv_sec = 1;
        tv.tv_usec = 0;
				
				debug("waiting data for/from client %s...\n", batostr(&clientBdAddr));
        int result2 = select(clientL2capSock + 1, &rfds, NULL, NULL, &tv);

        if (-1 == result2) {
          if (SIGINT == lastSignal || SIGKILL == lastSignal || SIGHUP == lastSignal) {
            if (SIGHUP == lastSignal) {
              result2 = 0;
            }
            break;
          }
        } else if (result2) {
          if (FD_ISSET(0, &rfds)) {
            len = read(0, stdinBuf, sizeof(stdinBuf));
						debug ("Read from stdin <%s>\n", stdinBuf);

            if (len <= 0) {
              break;
            }

            i = 0;
            while(stdinBuf[i] != '\n') {
              sscanf(&stdinBuf[i], "%02x", (unsigned int*)&l2capSockBuf[i / 2]);

              i += 2;
            }

            len = write(clientL2capSock, l2capSockBuf, (len - 1) / 2);
          }

          if (FD_ISSET(clientL2capSock, &rfds)) {
            len = read(clientL2capSock, l2capSockBuf, sizeof(l2capSockBuf));

            if (len <= 0) {
              break;
            }

            btSecurityLen = sizeof(btSecurity);
            memset(&btSecurity, 0, btSecurityLen);
            getsockopt(clientL2capSock, SOL_BLUETOOTH, BT_SECURITY, &btSecurity, &btSecurityLen);

            if (securityLevel != btSecurity.level) {
              securityLevel = btSecurity.level;

              const char *securityLevelString;

              switch(securityLevel) {
                case BT_SECURITY_LOW:
                  securityLevelString = "low";
                  break;

                case BT_SECURITY_MEDIUM:
                  securityLevelString = "medium";
                  break;

                case BT_SECURITY_HIGH:
                  securityLevelString = "high";
                  break;

                default:
                  securityLevelString = "unknown";
                  break;
              }

              printf("security %s\n", securityLevelString);
            }

            printf("data ");
						debug ("Read from client: \n");
            for(i = 0; i < len; i++) {
              printf("%02x", ((int)l2capSockBuf[i]) & 0xff);
              debug("%02x\n", ((int)l2capSockBuf[i]) & 0xff);
            }
            printf("\n");
          }
        }
      }

      printf("disconnect %s\n", batostr(&clientBdAddr));
      debug("disconnect %s\n", batostr(&clientBdAddr));
			
      close(clientL2capSock);
    }
  }

  printf("close\n");
  debug("close\n");
  close(serverL2capSock);

  return 0;
}

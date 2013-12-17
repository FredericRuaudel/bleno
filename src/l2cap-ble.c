#include <errno.h>
#include <signal.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>

#define ATT_CID 4
#define DATA_ALLOC_CHUNK 255

int lastSignal = 0;

typedef struct
{
	size_t size;
	size_t current_offset;
	char* buffer_data;
} Buffer;

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

Buffer* newBuffer()
{
	Buffer* newbuffer = (Buffer*)malloc(sizeof(Buffer));
	newbuffer->size = DATA_ALLOC_CHUNK;
	newbuffer->current_offset = 0;
	newbuffer->buffer_data = (char*)malloc(newbuffer->size*sizeof(char));

	return newbuffer;
}

void freeBuffer(Buffer** buffer)
{
	free((*buffer)->buffer_data);
	(*buffer)->buffer_data = NULL;
	free (buffer);
	buffer = NULL;
}

void appendData (Buffer* buffer, const char* newdata, size_t newdata_length)
{
	debug ("Will add %d byte to buffer which have %d size and %d offset\n", newdata_length, buffer->size, buffer->current_offset); 
	while (buffer->size <= buffer->current_offset + newdata_length)
	{
		buffer->size += DATA_ALLOC_CHUNK;
		char* tmp = realloc(buffer->buffer_data, buffer->size * sizeof(char));
		if (!tmp)
		{
			perror("Can't reallocate such memory\n");
			exit(-1);
		}
		buffer->buffer_data = tmp;
	}

	int i;
	for (i = 0; i < newdata_length; i++)
	{
		buffer->buffer_data[buffer->current_offset + i] = newdata[i];
		buffer->current_offset++;
	}

	debug ("Added %d byte to buffer which now have %d size and %d offset\n", newdata_length, buffer->size, buffer->current_offset); 
}

void popBufferData(Buffer* buffer, size_t data_length_to_pop)
{
	debug("Will pop %d value from buffer which have %d size and %d offset\n", data_length_to_pop, buffer->size, buffer->current_offset);
	int left_data_length = buffer->current_offset - data_length_to_pop;
	int i;
	for (i = 0; i < left_data_length; i++)
	{
		buffer->buffer_data[i] = buffer->buffer_data[data_length_to_pop+i];
	}
	buffer->current_offset = left_data_length;
	debug("Poped %d value from buffer which now have %d size and %d offset\n", data_length_to_pop, buffer->size, buffer->current_offset);
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
  fd_set wfds;
  struct timeval tv;

  char stdinBuf[256 * 2 + 1];
  char l2capSockBuf[256];
  int len;
  int i;
	Buffer* l2capSockBuffer = newBuffer();

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

	debug ("binding %s\n", (result == -1) ? strerror(errno) : "success");
  printf("bind %s\n", (result == -1) ? strerror(errno) : "success");

  result = listen(serverL2capSock, 1);

  debug("listen %s\n", (result == -1) ? strerror(errno) : "success");
  printf("listen %s\n", (result == -1) ? strerror(errno) : "success");

  while (result != -1) {
    FD_ZERO(&afds);
    FD_SET(serverL2capSock, &afds);

    tv.tv_sec = 1;
    tv.tv_usec = 0;

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
				FD_ZERO(&wfds);
				if (l2capSockBuffer->current_offset > 0)
				{
					debug("Have %d bytes of data -> checking write from socket\n", l2capSockBuffer->current_offset);
					FD_SET(clientL2capSock, &wfds);
				}

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        result = select(clientL2capSock + 1, &rfds, &wfds, NULL, &tv);

        if (-1 == result) {
          if (SIGINT == lastSignal || SIGKILL == lastSignal || SIGHUP == lastSignal) {
            if (SIGHUP == lastSignal) {
              result = 0;
            }
            break;
          }
        } else if (result) {
          if (FD_ISSET(0, &rfds)) {
						debug("***read to stdin ready\n");
            len = read(0, stdinBuf, sizeof(stdinBuf));
						debug ("Reading from stdin <%s>\n", stdinBuf);

            if (len <= 0) {
              break;
            }

            i = 0;
            while(stdinBuf[i] != '\n') {
              sscanf(&stdinBuf[i], "%02x", (unsigned int*)&l2capSockBuf[i / 2]);

              i += 2;
            }

						appendData(l2capSockBuffer, l2capSockBuf, len);
					}
					
					if (FD_ISSET(clientL2capSock, &wfds))
					{
						size_t data_length = l2capSockBuffer->current_offset;
						debug("***write to socket ready - have %d bytes in buffer\n", data_length);
						if (data_length > 0)
						{
							len = write(clientL2capSock, l2capSockBuffer->buffer_data, data_length);
							popBufferData(l2capSockBuffer, len);
							debug ("write %d bytes to client socket\n", len);
						}
          }

          if (FD_ISSET(clientL2capSock, &rfds)) {
						debug("***read to socket ready\n");
            len = read(clientL2capSock, l2capSockBuf, sizeof(l2capSockBuf));

            if (len <= 0) {
              break;
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
	freeBuffer(&l2capSockBuffer);

  return 0;
}

#include "lwip/opt.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/tcp.h"
#include "server.h" /* tcpecho_raw.h */

#if LWIP_TCP && LWIP_CALLBACK_API

static struct tcp_pcb *server_pcb;

enum server_states
{
  ES_NONE = 0,
  ES_ACCEPTED,
  ES_RECEIVED,
  ES_CLOSING
};

struct server_state
{
  u8_t state;
  u8_t retries;
  struct tcp_pcb *pcb;
  /* pbuf (chain) to recycle */
  struct pbuf *p;
};

static void
server_raw_free(struct server_state *es)
{
  if (es != NULL) { /* buffer를 먼저 free */
    if (es->p) {
      /* free the buffer chain if present */
      pbuf_free(es->p);
    }
    /* pcb를 free */
    mem_free(es);
  }
}

static void
server_raw_close(struct tcp_pcb *tpcb, struct server_state *es)
{ /* 등록된 callback 함수를 모두 제거 */
  tcp_arg(tpcb, NULL);
  tcp_sent(tpcb, NULL);
  tcp_recv(tpcb, NULL);
  tcp_err(tpcb, NULL);
  tcp_poll(tpcb, NULL, 0);

  server_raw_free(es);

  printf("close connection\n");
  tcp_close(tpcb);
}

static void
server_raw_send(struct tcp_pcb *tpcb, struct server_state *es)
{
  struct pbuf *ptr;
  err_t wr_err = ERR_OK;

  while ((wr_err == ERR_OK) &&
         (es->p != NULL) &&
         (es->p->len <= tcp_sndbuf(tpcb))) {
    ptr = es->p;

    /* enqueue data for transmission */
    wr_err = tcp_write(tpcb, ptr->payload, ptr->len, 1);
    if (wr_err == ERR_OK) {
      u16_t plen;

      plen = ptr->len;
      /* continue with next pbuf in chain (if any) */
      es->p = ptr->next;
      if(es->p != NULL) {
        /* new reference! */
        pbuf_ref(es->p);
      }
      /* chop first pbuf from chain */
      pbuf_free(ptr);
      /* we can read more data now */
      tcp_recved(tpcb, plen);
    } else if(wr_err == ERR_MEM) {
      /* we are low on memory, try later / harder, defer to poll */
      es->p = ptr;
    } else {
      /* other problem ?? */
    }
  }
}

static void
server_raw_error(void *arg, err_t err)
{
  struct server_state *es;

  LWIP_UNUSED_ARG(err);

  es = (struct server_state *)arg;

  server_raw_free(es);
}

static err_t
server_raw_poll(void *arg, struct tcp_pcb *tpcb)
{
  err_t ret_err;
  struct server_state *es;

  es = (struct server_state *)arg;
  if (es != NULL) {
    if (es->p != NULL) {
      /* there is a remaining pbuf (chain)  */
      server_raw_send(tpcb, es);
    } else {
      /* no remaining pbuf (chain)  */
      if(es->state == ES_CLOSING) {
        server_raw_close(tpcb, es);
      }
    }
	printf("server poll message\n");
    ret_err = ERR_OK;
  } else {
    /* nothing to be done */
    tcp_abort(tpcb);
    ret_err = ERR_ABRT;
  }
  return ret_err;
}

static err_t
server_raw_sent(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
  struct server_state *es;

  LWIP_UNUSED_ARG(len);

  es = (struct server_state *)arg;
  es->retries = 0;

  if(es->p != NULL) {
    /* still got pbufs to send */
    tcp_sent(tpcb, server_raw_sent);
    server_raw_send(tpcb, es);
  } else {
    /* no more pbufs to send */
    if(es->state == ES_CLOSING) {
      server_raw_close(tpcb, es);
    }
  }
  printf("server sent message\n");
  return ERR_OK;
}

static err_t
server_raw_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
  struct server_state *es;
  err_t ret_err;

  LWIP_ASSERT("arg != NULL",arg != NULL);
  es = (struct server_state *)arg;
  if (p == NULL) {
    /* remote host closed connection */
    es->state = ES_CLOSING;
    if(es->p == NULL) {
      /* we're done sending, close it */
      server_raw_close(tpcb, es);
    } else {
      /* we're not done yet */
      server_raw_send(tpcb, es);
    }
    ret_err = ERR_OK;
  } else if(err != ERR_OK) {
    /* cleanup, for unknown reason */
    LWIP_ASSERT("no pbuf expected here", p == NULL);
    ret_err = err;
  }
  else if(es->state == ES_ACCEPTED) {
    /* first data chunk in p->payload */
	printf("Server got SYN packet from client\n");
    es->state = ES_RECEIVED;
    /* store reference to incoming pbuf (chain) */
    es->p = p;
    server_raw_send(tpcb, es);
    ret_err = ERR_OK;
  } else if (es->state == ES_RECEIVED) {
    /* read some more data */
    if(es->p == NULL) {
      es->p = p;
      server_raw_send(tpcb, es);
    } else {
      struct pbuf *ptr;

      /* chain pbufs to the end of what we recv'ed previously  */
      ptr = es->p;
      pbuf_cat(ptr,p);
    }
    ret_err = ERR_OK;
  } else {
    /* unknown es->state, trash data  */
    tcp_recved(tpcb, p->tot_len);
    pbuf_free(p);
    ret_err = ERR_OK;
  }
  printf("server received message\n");
  return ret_err;
}

static err_t
server_raw_accept(void *arg, struct tcp_pcb *newpcb, err_t err)
{
  err_t ret_err;
  struct server_state *es;

  LWIP_UNUSED_ARG(arg);
  if ((err != ERR_OK) || (newpcb == NULL)) {
    return ERR_VAL;
  }

  /* Unless this pcb should have NORMAL priority, set its priority now.
     When running out of pcbs, low priority pcbs can be aborted to create
     new pcbs of higher priority. */
  tcp_setprio(newpcb, TCP_PRIO_MIN);

  es = (struct server_state *)mem_malloc(sizeof(struct server_state));
  if (es != NULL) {
    es->state = ES_ACCEPTED;
    es->pcb = newpcb;
    es->retries = 0;
    es->p = NULL;
    /* pass newly allocated es to our callbacks */
    tcp_arg(newpcb, es);
    tcp_recv(newpcb, server_raw_recv);
    tcp_err(newpcb, server_raw_error);
    tcp_poll(newpcb, server_raw_poll, 0);
    tcp_sent(newpcb, server_raw_sent);
    ret_err = ERR_OK;
  } else {
    ret_err = ERR_MEM;
  }
  printf("open connection\n");
  return ret_err;
}

void
server_raw_init(void)
{
  server_pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
  if (server_pcb != NULL) {
    err_t err;
/*
	ip_addr_t server_ip;
	IP_ADDR4(&server_ip, 192, 168, 1, 100);
  
	err = tcp_bind(server_pcb, &server_ip, 7);
	*/
	err = tcp_bind(server_pcb, IP_ANY_TYPE, 7);
    if (err == ERR_OK) {
		printf("server init success\n");
		server_pcb = tcp_listen(server_pcb);
		/* server_pcb->state = 0;*/
		tcp_accept(server_pcb, server_raw_accept);

    } else {
      /* abort? output diagnostic? */
    }
  } else {
    /* abort? output diagnostic? */
  }
}

#endif /* LWIP_TCP && LWIP_CALLBACK_API */


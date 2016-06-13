KMOD	= jailfsstat
SRCS	= jailfsstat.c vnode_if.h
CFLAGS	= -Wall

.include <bsd.kmod.mk>

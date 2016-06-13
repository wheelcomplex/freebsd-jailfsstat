/*
 * jailfsstat - Show only filesystems mounted in jail.
 *
 * (c) 2002 Pawel Jakub Dawidek <nick@garage.freebsd.pl>
 *
 * $Log: jailfsstat.c,v $
 * Revision 1.5  2002/10/02 11:47:53  jules
 * When chroot directory is also mount-point, statfs() and fstatfs()
 * should return "/" instead of "".
 *
 * Revision 1.4  2002/10/01 23:36:34  jules
 * When calling fstatfs(2) with descryptor from outside of jail
 * f_mntonname will be equal to "/".
 *
 * Revision 1.3  2002/10/01 20:55:23  jules
 * Now getfsstat(2) gets mount point of chroot directory of
 * jail and return it with path "/".
 *
 * Revision 1.2  2002/10/01 16:02:19  jules
 * - Implemented statfs() and fstatfs() catching.
 * - Removed redundant #includes.
 *
 * Revision 1.1.1.1  2002/10/01 15:18:38  jules
 * Initial import into CVS.
 *
 */

static const char rcsid[] =
	"$Id: jailfsstat.c,v 1.5 2002/10/02 11:47:53 jules Exp $";

#include <sys/param.h>
#include <sys/sysproto.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/mount.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/sysent.h>
#include <sys/vnode.h>
#include <sys/namei.h>

static sy_call_t	*old_getfsstat,
			*old_statfs,
			*old_fstatfs;

struct  namecache {
	LIST_ENTRY(namecache)	nc_hash;	/* hash chain */
	LIST_ENTRY(namecache)	nc_src;		/* source vnode list */
	TAILQ_ENTRY(namecache)	nc_dst;		/* destination vnode list */
	struct vnode	*nc_dvp;		/* vnode of parent of name */
	struct vnode	*nc_vp;			/* vnode the name refers to */
	u_char		 nc_flag;		/* flag bits */
	u_char		 nc_nlen;		/* length of name */
	char		 nc_name[0];		/* segment name */
};

static int
getchrootdir(struct proc *p, char *out, size_t size)
{
	struct namecache	*ncp;
	struct filedesc	*fdp;
	register struct vnode	*vp;
	register int 	i;
	char		*bp, *buf;
	int		slash_prefixed;

	if (size < 2)
		return (EINVAL);
	if (size > MAXPATHLEN)
		size = MAXPATHLEN;

	fdp = p->p_fd;
	if ((vp = fdp->fd_jdir) == NULL) {
		strncpy(out, "/", size - 1);
		out[size - 1] = '\0';
		return (0);
	}

	buf = bp = malloc(size, M_TEMP, M_WAITOK);
	bp += size - 1;
	*bp = '\0';
	slash_prefixed = 0;

	for (; vp != rootvnode;) {
		if (vp->v_flag & VROOT) {
			if (vp->v_mount == NULL) {	/* forced unmount */
				free(buf, M_TEMP);
				return (EBADF);
			}
			vp = vp->v_mount->mnt_vnodecovered;
			continue;
		}
		if (vp->v_dd->v_id != vp->v_ddid) {
			free(buf, M_TEMP);
			return (ENOTDIR);
		}
		ncp = TAILQ_FIRST(&vp->v_cache_dst);
		if (!ncp) {
			free(buf, M_TEMP);
			return (ENOENT);
		}
		if (ncp->nc_dvp != vp->v_dd) {
			free(buf, M_TEMP);
			return (EBADF);
		}
		for (i = ncp->nc_nlen - 1; i >= 0; i--) {
			if (bp == buf) {
				free(buf, M_TEMP);
				return (ENOMEM);
			}
			*--bp = ncp->nc_name[i];
		}
		if (bp == buf) {
			free(buf, M_TEMP);
			return (ENOMEM);
		}
		*--bp = '/';
		slash_prefixed = 1;
		vp = vp->v_dd;
	}
	if (!slash_prefixed) {
		if (bp == buf) {
			free(buf, M_TEMP);
			return (ENOMEM);
		}
		*--bp = '/';
	}

	strncpy(out, bp, size - 1);
	out[size - 1] = '\0';

	free(buf, M_TEMP);

	return (0);
}

static int
parsepath(char *path, char *chrootdir)
{
	register char	*p, *q;

	if (strcmp(chrootdir, "/") == 0)
		return (1);

	if (strncmp(path, chrootdir, strlen(chrootdir) - 1) != 0)
		return (0);

	for (p = path, q = path + strlen(chrootdir); *q != '\0'; ++p, ++q)
		*p = *q;
	*p = '\0';

	return (1);
}

static int
chrmp(register struct proc *p, char *path, struct mount **mp)
{
	struct nameidata	nd;
	int	error;

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, path, p);
	if ((error = namei(&nd)) != 0) {
		uprintf("CHRMP: %d\n", error);
		return (error);
	}
	*mp = nd.ni_vp->v_mount;
        NDFREE(&nd, NDF_ONLY_PNBUF);
        vrele(nd.ni_vp);

	return (0);
}

static int
jail_getfsstat(register struct proc *p, register struct getfsstat_args *uap)
{
	register struct mount	*mp, *nmp;
	struct mount	*cmp;
	register struct statfs	*sp;
	struct statfs	*tsp;
	caddr_t	sfsp;
	long	count, maxcount, error;
	static char	chrootdir[MAXPATHLEN];
	int	ret;

	if (p->p_prison == NULL)
		return old_getfsstat(p, uap);

	if ((ret = getchrootdir(p, chrootdir, sizeof chrootdir)) != 0)
		return (ret);

	if ((ret = chrmp(p, "/", &cmp)) != 0)
		return (ret);

	maxcount = SCARG(uap, bufsize) / sizeof(struct statfs);
	sfsp = (caddr_t)SCARG(uap, buf);
	count = 0;
	simple_lock(&mountlist_slock);
	for (mp = TAILQ_FIRST(&mountlist); mp != NULL; mp = nmp) {
		if (vfs_busy(mp, LK_NOWAIT, &mountlist_slock, p)) {
			nmp = TAILQ_NEXT(mp, mnt_list);
			continue;
		}
		if (sfsp != NULL && count < maxcount) {
			sp = &mp->mnt_stat;
			/*
			 * If MNT_NOWAIT or MNT_LAZY is specified, do not
			 * refresh the fsstat cache. MNT_NOWAIT or MNT_LAZY
			 * overrides MNT_WAIT.
			 */
			if (((SCARG(uap, flags) & (MNT_LAZY|MNT_NOWAIT)) == 0 ||
			    (SCARG(uap, flags) & MNT_WAIT)) &&
			    (error = VFS_STATFS(mp, sp, p))) {
				simple_lock(&mountlist_slock);
				nmp = TAILQ_NEXT(mp, mnt_list);
				vfs_unbusy(mp, p);
				continue;
			}
			sp->f_flags = mp->mnt_flag & MNT_VISFLAGMASK;
			error = copyout((caddr_t)sp, sfsp, sizeof(*sp));
			if (error) {
				vfs_unbusy(mp, p);
				return (error);
			}
			tsp = (struct statfs *)sfsp;
			if (cmp == mp) {
				strcpy(tsp->f_mntonname, "/");
			} else if (!parsepath(tsp->f_mntonname, chrootdir)) {
				simple_lock(&mountlist_slock);
				nmp = TAILQ_NEXT(mp, mnt_list);
				vfs_unbusy(mp, p);
				continue;
			}
			sfsp += sizeof(*sp);
		}
		count++;
		simple_lock(&mountlist_slock);
		nmp = TAILQ_NEXT(mp, mnt_list);
		vfs_unbusy(mp, p);
	}
	simple_unlock(&mountlist_slock);
	if (sfsp && count > maxcount)
		p->p_retval[0] = maxcount;
	else
		p->p_retval[0] = count;
	return (0);
}

static int
jail_statfs(register struct proc *p, register struct statfs_args *uap)
{
	int	error;
	static char	chrootdir[MAXPATHLEN];

	if ((error = statfs(p, uap)) != 0)
		return (error);

	if (p->p_prison == NULL)
		return (error);

	if ((error = getchrootdir(p, chrootdir, sizeof chrootdir)) != 0)
		return (error);

	if (!parsepath(uap->buf->f_mntonname, chrootdir) ||
	    *uap->buf->f_mntonname == '\0')
		strcpy(uap->buf->f_mntonname, "/");

	return (error);
}

static int
jail_fstatfs(register struct proc *p, register struct fstatfs_args *uap)
{
	int	error;
	static char	chrootdir[MAXPATHLEN];

	if ((error = fstatfs(p, uap)) != 0)
		return (error);

	if (p->p_prison == NULL)
		return (error);

	if ((error = getchrootdir(p, chrootdir, sizeof chrootdir)) != 0)
		return (error);

	if (!parsepath(uap->buf->f_mntonname, chrootdir) ||
	    *uap->buf->f_mntonname == '\0')
		strcpy(uap->buf->f_mntonname, "/");

	return (error);
}

static int
mod(struct module *module, int cmd, void *arg)
{
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		old_getfsstat = sysent[SYS_getfsstat].sy_call;
		sysent[SYS_getfsstat].sy_call = (sy_call_t *)jail_getfsstat;
		old_statfs = sysent[SYS_statfs].sy_call;
		sysent[SYS_statfs].sy_call = (sy_call_t *)jail_statfs;
		old_fstatfs = sysent[SYS_fstatfs].sy_call;
		sysent[SYS_fstatfs].sy_call = (sy_call_t *)jail_fstatfs;
		printf("\njailfsstat loaded.\n%s\n", rcsid);
		break;
	case MOD_UNLOAD:
		sysent[SYS_getfsstat].sy_call = old_getfsstat;
		sysent[SYS_statfs].sy_call = old_statfs;
		sysent[SYS_fstatfs].sy_call = old_fstatfs;
		printf("\njailfsstat unloaded.\n");
		break;
	default:
		error = EINVAL;
		break;
	}

	return error;
}

static moduledata_t jailfsstat_mod =
{
	"jailfsstat",
	mod,
	NULL
};

DECLARE_MODULE(jailfsstat, jailfsstat_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);

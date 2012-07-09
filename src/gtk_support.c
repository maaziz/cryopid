#if 1
#include <gtk/gtk.h>
#else
/* We don't really need Gtk devel libraries do we? */
#define GdkDisplay void
#define GdkDisplayManager void
#define GdkScreen void
#define GtkWindow void
#define GdkWindow void
#define GList void
#define GType void*
#define GTypeInstance void
#define GFunc void*
#define GTK_IS_WINDOW(x) (1) /* Bleh, live with the assertions */
#endif

#include <signal.h>
#include <unistd.h>

#include "cryopid.h"
#include "x.h"

char display_environ[80];
char xauthority_environ[80];
int need_gtk = 0;
int gtk_can_close_displays = 0;

void cryopid_migrate_gtk_windows()
{
    void *lm = find_linkmap((void*)0x8048000); /* FIXME: find dynamically */
#define find_symbol(name, rettype, params) \
    	rettype (*_##name)params = plt_resolve(lm, #name); \
    	if (_##name == NULL) \
	    return;
#define find_symbol_noprefix(name, rettype, params) \
    	rettype (*name)params = plt_resolve(lm, #name); \
    	if (name == NULL) \
	    return;
    find_symbol(gdk_display_get_default, GdkDisplay*, ());
    find_symbol(gdk_display_manager_get, GdkDisplayManager*, ());
    find_symbol(gdk_display_manager_set_default_display, void, (GdkDisplayManager*, GdkDisplay*));
    find_symbol(gdk_display_open, GdkDisplay*, (char*));
    find_symbol(gdk_display_get_default_screen, GdkScreen*, (GdkDisplay*));
    find_symbol(gdk_window_get_toplevels, GList*, ());
    find_symbol(gdk_window_get_user_data, void, (GdkWindow*,void**));
    find_symbol(gtk_window_set_screen, void, (GtkWindow*,GdkScreen*));
    find_symbol(g_list_foreach, void, (GList*,GFunc,void*));
    find_symbol(g_list_free, void, (GList*));
    find_symbol(gdk_display_close, void, (GdkDisplay*));
    find_symbol_noprefix(gtk_window_get_type, GType, (void));
    find_symbol_noprefix(g_type_check_instance_is_a, int, (GTypeInstance*, GType));
    find_symbol(setenv, int, (const char*, const char*, int));

    GList *top_levels = _gdk_window_get_toplevels();

    int need_moving = 0;
    void need_moving_func(GdkWindow *w, void *nothing) {
	GtkWindow *wd;
	_gdk_window_get_user_data(w, (void*)&wd);
	if (GTK_IS_WINDOW(wd))
	    need_moving = 1;
    }
    _g_list_foreach(top_levels, (GFunc)need_moving_func, NULL);
    if (!need_moving)
	return;

    _setenv("XAUTHORITY", xauthority_environ, 1);
    GdkDisplay *old_display = _gdk_display_get_default();
    GdkDisplay *new_display = _gdk_display_open(display_environ);
    GdkDisplayManager *m = _gdk_display_manager_get();
    _gdk_display_manager_set_default_display(m, new_display);

    GdkScreen *screen = _gdk_display_get_default_screen(new_display);
    void move_it(GdkWindow *w, GdkScreen *s) {
	GtkWindow *wd;
	_gdk_window_get_user_data(w, (void*)&wd);
	if (GTK_IS_WINDOW(wd))
	    _gtk_window_set_screen (wd, s);
    }
    _g_list_foreach(top_levels, (GFunc)move_it, (void*)screen);
    _g_list_free(top_levels);

    /* We need a recent enough Gtk+ to be able to close displays without
     * crashing (Gtk+ 2.10, or some CVS version thereof).
     */
    if (gtk_can_close_displays)
	_gdk_display_close(old_display);
}

void x_responder(int fd) {
    char buf[4096];
    int len;
    unsigned short seq = 0;
    static char reply[] =
	"\1\1\0\0\0\0\0\0<\0`\3\4\0\0\0\0\0\0\0\360R\214\3\210\357\37\t\0\0\0\0";
    while ((len = read(fd, buf, sizeof(buf))) > 0) {
	char *p = buf;
	while (p - buf < len) {
	    char *rstart = p;
	    int rlen = p[3] << 10 | p[2] << 2;
	    if (rlen > len - (p-buf))
		rlen = len - (p-buf);
#if 0
	    printf("Request: %s (%d) (len %d)\n", request_to_str(p[0]), p[0], rlen);
	    p += 4;
	    while (p - rstart < rlen) {
		int i;
		printf("\t");
		for (i = 0; i < 16; i++) {
		    if (p - rstart >= rlen)
			break;
		    printf("%.02x ", (unsigned char)*p);
		    p++;
		}
		printf("\n");
	    }
#endif
	    *(unsigned short*)(reply+2) = ++seq;
	    write(fd, reply, sizeof(reply)-1);
	    p = rstart + rlen;
	}
    }
    close(fd);
    _exit(0);
}

/* vim:set ts=8 sw=4 noet: */

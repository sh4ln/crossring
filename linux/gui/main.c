// CROSSRING Linux - GTK4 GUI Main Window
#include <gtk/gtk.h>
#include <stdbool.h>

typedef struct {
    GtkWidget* window;
    GtkWidget* stack;
    GtkWidget* events_list;
    GtkWidget* persistence_list;
    GtkWidget* whitelist_list;
    GtkWidget* status_label;
    
    bool connected;
    int socket_fd;
} CrossringApp;

static CrossringApp app = {0};

// Event row widget
static GtkWidget* create_event_row(const char* timestamp, 
                                    const char* exe_path,
                                    int pid,
                                    const char* decision) {
    GtkWidget* row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_set_margin_start(row, 10);
    gtk_widget_set_margin_end(row, 10);
    gtk_widget_set_margin_top(row, 5);
    gtk_widget_set_margin_bottom(row, 5);
    
    GtkWidget* time_label = gtk_label_new(timestamp);
    gtk_widget_add_css_class(time_label, "dim-label");
    gtk_box_append(GTK_BOX(row), time_label);
    
    GtkWidget* exe_label = gtk_label_new(exe_path);
    gtk_widget_set_hexpand(exe_label, TRUE);
    gtk_label_set_xalign(GTK_LABEL(exe_label), 0);
    gtk_box_append(GTK_BOX(row), exe_label);
    
    char pid_str[16];
    snprintf(pid_str, sizeof(pid_str), "%d", pid);
    GtkWidget* pid_label = gtk_label_new(pid_str);
    gtk_box_append(GTK_BOX(row), pid_label);
    
    GtkWidget* decision_label = gtk_label_new(decision);
    if (strcmp(decision, "Allowed") == 0) {
        gtk_widget_add_css_class(decision_label, "success");
    } else if (strcmp(decision, "Denied") == 0) {
        gtk_widget_add_css_class(decision_label, "error");
    }
    gtk_box_append(GTK_BOX(row), decision_label);
    
    return row;
}

// Navigation button callback
static void on_nav_clicked(GtkWidget* button, gpointer user_data) {
    const char* page = (const char*)user_data;
    gtk_stack_set_visible_child_name(GTK_STACK(app.stack), page);
}

// Build sidebar
static GtkWidget* build_sidebar() {
    GtkWidget* sidebar = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_size_request(sidebar, 200, -1);
    gtk_widget_add_css_class(sidebar, "sidebar");
    
    // Logo
    GtkWidget* logo_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_set_margin_start(logo_box, 15);
    gtk_widget_set_margin_top(logo_box, 20);
    gtk_widget_set_margin_bottom(logo_box, 20);
    
    GtkWidget* logo_label = gtk_label_new("🛡️ CROSSRING");
    gtk_widget_add_css_class(logo_label, "title-2");
    gtk_box_append(GTK_BOX(logo_box), logo_label);
    gtk_box_append(GTK_BOX(sidebar), logo_box);
    
    // Navigation buttons
    const char* pages[] = {"events", "persistence", "network", "whitelist", "settings"};
    const char* labels[] = {"📋 Events", "🔒 Persistence", "🌐 Network", "✅ Whitelist", "⚙️ Settings"};
    
    for (int i = 0; i < 5; i++) {
        GtkWidget* button = gtk_button_new_with_label(labels[i]);
        gtk_widget_add_css_class(button, "flat");
        gtk_widget_set_halign(button, GTK_ALIGN_START);
        g_signal_connect(button, "clicked", G_CALLBACK(on_nav_clicked), (gpointer)pages[i]);
        gtk_box_append(GTK_BOX(sidebar), button);
    }
    
    // Spacer
    GtkWidget* spacer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_vexpand(spacer, TRUE);
    gtk_box_append(GTK_BOX(sidebar), spacer);
    
    // Status
    app.status_label = gtk_label_new("⚪ Disconnected");
    gtk_widget_add_css_class(app.status_label, "dim-label");
    gtk_widget_set_margin_start(app.status_label, 15);
    gtk_widget_set_margin_bottom(app.status_label, 15);
    gtk_label_set_xalign(GTK_LABEL(app.status_label), 0);
    gtk_box_append(GTK_BOX(sidebar), app.status_label);
    
    return sidebar;
}

// Build events page
static GtkWidget* build_events_page() {
    GtkWidget* page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_start(page, 20);
    gtk_widget_set_margin_end(page, 20);
    gtk_widget_set_margin_top(page, 20);
    
    GtkWidget* header = gtk_label_new("Process Events");
    gtk_widget_add_css_class(header, "title-1");
    gtk_label_set_xalign(GTK_LABEL(header), 0);
    gtk_box_append(GTK_BOX(page), header);
    
    // Scrolled list
    GtkWidget* scroll = gtk_scrolled_window_new();
    gtk_widget_set_vexpand(scroll, TRUE);
    
    app.events_list = gtk_list_box_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), app.events_list);
    gtk_box_append(GTK_BOX(page), scroll);
    
    // Add sample events
    gtk_list_box_append(GTK_LIST_BOX(app.events_list),
        create_event_row("13:00:05", "/usr/bin/firefox", 1234, "Allowed"));
    gtk_list_box_append(GTK_LIST_BOX(app.events_list),
        create_event_row("13:00:10", "/tmp/suspicious.sh", 1235, "Denied"));
    
    return page;
}

// Build main content stack
static GtkWidget* build_content() {
    app.stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(app.stack), GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    
    gtk_stack_add_named(GTK_STACK(app.stack), build_events_page(), "events");
    
    // Placeholder pages
    const char* placeholders[] = {"persistence", "network", "whitelist", "settings"};
    for (int i = 0; i < 4; i++) {
        GtkWidget* placeholder = gtk_label_new(placeholders[i]);
        gtk_stack_add_named(GTK_STACK(app.stack), placeholder, placeholders[i]);
    }
    
    return app.stack;
}

// CSS styling
static const char* css = 
    ".sidebar { background-color: #1a1a2e; }"
    ".title-1 { font-size: 24px; font-weight: bold; }"
    ".title-2 { font-size: 18px; font-weight: bold; color: #e94560; }"
    ".success { color: #4ade80; }"
    ".error { color: #ef4444; }"
    ".dim-label { color: #888; font-size: 12px; }";

static void on_activate(GtkApplication* gtk_app, gpointer user_data) {
    // Apply CSS
    GtkCssProvider* provider = gtk_css_provider_new();
    gtk_css_provider_load_from_data(provider, css, -1);
    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(),
        GTK_STYLE_PROVIDER(provider),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    
    // Create window
    app.window = gtk_application_window_new(gtk_app);
    gtk_window_set_title(GTK_WINDOW(app.window), "CROSSRING");
    gtk_window_set_default_size(GTK_WINDOW(app.window), 1200, 700);
    
    // Main layout
    GtkWidget* main_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_box_append(GTK_BOX(main_box), build_sidebar());
    gtk_box_append(GTK_BOX(main_box), build_content());
    
    gtk_window_set_child(GTK_WINDOW(app.window), main_box);
    gtk_window_present(GTK_WINDOW(app.window));
}

int main(int argc, char* argv[]) {
    GtkApplication* gtk_app = gtk_application_new("com.crossring.gui", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(gtk_app, "activate", G_CALLBACK(on_activate), NULL);
    
    int status = g_application_run(G_APPLICATION(gtk_app), argc, argv);
    g_object_unref(gtk_app);
    
    return status;
}

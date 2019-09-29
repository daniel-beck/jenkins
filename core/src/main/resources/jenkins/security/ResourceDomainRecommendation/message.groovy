package jenkins.security.ResourceDomainRecommendation

def f=namespace(lib.FormTagLib)

dl {
    div(class: "alert alert-info") {
        a(name: "resource-root-url")
        form(method: "post", action: "${rootURL}/${my.url}/act") {
            f.submit(name: 'redirect', value: _("Go to resource root URL configuration"))
            f.submit(name: 'dismiss', value: _("Dismiss"))
        }

        raw(_("blurb"))
    }
}

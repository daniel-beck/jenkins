package jenkins.security.ResourceDomainRecommendation

dl {
    div(class: "alert alert-info") {

        form(method: "post", action: "${rootURL}/${my.url}/act") {
            f.submit(name: 'redirect', value: _("Go to resource root URL configuration"))
            f.submit(name: 'dismiss', value: _("Dismiss"))
        }

        text(_("blurb"))
    }
}

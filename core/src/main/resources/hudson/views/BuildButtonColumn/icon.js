Behaviour.specify(".build-button-column-icon-reference-holder", 'build-button-column', 0, function (e) {
    var id = e.getAttribute('data-id');
    var icon = document.getElementById(id);

    icon.onclick = function(el) {
        new Ajax.Request(this.getAttribute('data-url'));
        hoverNotification(this.getAttribute('data-notification'), this, -100);
        return false;
    }
});

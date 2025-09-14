from flask_wtf import FlaskForm

class CSRFOnlyForm(FlaskForm):
    """
    Empty form used solely to emit a CSRF token via form.hidden_tag().

    Even without defining any fields, FlaskForm injects a hidden CSRF field.
    THat's why {{form.hidden_tag()}} works and why form.validate_on_submit() will validate the token.
    """
    pass
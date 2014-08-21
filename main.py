#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import cgi
form = """
<form method="get" >
    <input type ="password" name="q">
    <input type="submit">
</form>"""

ROT13form = """
<html>
  <head>
    <title>Unit 2 Rot 13</title>
  </head>

  <body>
    <h2>Enter some text to ROT13:</h2>
    <form method="post">
      <textarea name="text" style="height: 100px; width: 400px;">%(newText)s</textarea>
      <br>
      <input type="submit">
    </form>
  </body>

</html>
"""

inputForm = """
<html>
  <head>
    <title>Sign Up</title>
    <style type="text/css">
      .label {text-align: right}
      .error {color: red}
    </style>

  </head>

  <body>
    <h2>Signup</h2>
    <form method="post">
      <table>
        <tr>
          <td class="label">
            Username
          </td>
          <td>
            <input type="text" name="username" value="">
          </td>
          <td class="error">
          %(errorUsername)s  
          </td>
        </tr>

        <tr>
          <td class="label">
            Password
          </td>
          <td>
            <input type="password" name="password" value="">
          </td>
          <td class="error">
          %(errorPassword)s 
          </td>
        </tr>

        <tr>
          <td class="label">
            Verify Password
          </td>
          <td>
            <input type="password" name="verify" value="">
          </td>
          <td class="error">
          %(errorVerify)s 
          </td>
        </tr>

        <tr>
          <td class="label">
            Email (optional)
          </td>
          <td>
            <input type="text" name="email" value="">
          </td>
          <td class="error">
          %(errorEmail)s 
          </td>
        </tr>
      </table>

      <input type="submit">
    </form>
  </body>

</html>
"""

class MainHandler(webapp2.RequestHandler):
    def get(self):  
        self.response.out.write(form)

#class TestHandler(webapp2.RequestHandler):
#    def post(self):
#        q=self.request.get("q")
#        #self.response.headers['Content-Type'] = 'text/plain'
#        self.response.out.write(q)
#        self.response.out.write(self.request)

def ROTencode(inputStr):
    newStr = ""
    for c in inputStr:    
        if ord(c) <= ord('z') and ord(c) >= ord('a'):
            intNewChar = (ord(c) + 13 - ord('a')) % 26
            encodedChar = chr(ord('a') + intNewChar)
            newStr = newStr + encodedChar
        elif ord(c) <= ord('Z') and ord(c) >= ord('A'):
            intNewChar = (ord(c) + 13 - ord('A')) % 26
            encodedChar = chr(ord('A') + intNewChar)
            newStr = newStr + encodedChar
        else:
            newStr = newStr + c
    return newStr
    

class EncodeHandler(webapp2.RequestHandler):
    def get(self):
        self.response.out.write(ROT13form % {"newText":""})
    def post(self):
        txtInput = self.request.get("text")
        encodedText = ROTencode(txtInput)
        #escapedText = cgi.escape(encodedText, quote = True)
        self.response.out.write(ROT13form % {"newText":encodedText})

class SignUpHandler(webapp2.RequestHandler):
    def get(self):
        self.response.out.write(inputForm % {"errorUsername":"", "errorPassword":"", "errorVerify":"","errorEmail":""})
    def post(self):
        txtUsername = self.request.get("username")
        txtPassword = self.request.get("password")
        txtVerify = self.request.get("verify")
        txtUsername = self.request.get("username")
  
app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/ROT13', EncodeHandler),
    ('/SignUp', SignUpHandler)
], debug=True)

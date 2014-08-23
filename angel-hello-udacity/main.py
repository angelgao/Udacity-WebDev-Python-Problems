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
import cgi #for character escaping
import re #for regular expression

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

</html>"""

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
            <input type="text" name="username" value=%(username)s>
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
            <input type="text" name="email" value=%(email)s>
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

class ThanksHandler(webapp2.RequestHandler):
    def get(self):
        self.response.out.write("")

class SignUpHandler(webapp2.RequestHandler):
    def get(self):
        self.response.out.write(printForm())
    def post(self):
        txtUsername = self.request.get("username")
        txtPassword = self.request.get("password")
        txtVerify = self.request.get("verify")
        txtEmail = self.request.get("email")
        USER_RE = "^[a-zA-Z0-9_-]{3,20}$"
        PASS_RE = "^.{3,20}$"
        EMAIL_RE = "^[\S]+@[\S]+\.[\S]+$"
        dict = {'UsernameError': "",
                'PasswordError':"",
                'VerifyError':"",
                'EmailError':"",
                'Username':txtUsername,
                'Email':txtEmail}
        validated = None
        if(not verifyWithRegex(txtUsername, USER_RE)):
            #self.response.out.write(inputForm % {"errorUsername":"That's not a valid username.", "errorPassword":"", "errorVerify":"","errorEmail":""})
            #self.response.out.write(printForm(UsernameError="That's not a valid username.", username=txtUsername, email=txtEmail))
            dict['UsernameError'] = "That's not a valid username."
            validated = True
            
        if(not verifyWithRegex(txtPassword, PASS_RE)):
            #self.response.out.write(inputForm % {"errorUsername":"", "errorPassword":"That wasn't a valid password.", "errorVerify":"","errorEmail":""})
            #self.response.out.write(printForm(PasswordError="That wasn't a valid password.", username=txtUsername, email=txtEmail))
            dict['PasswordError'] = "That wasn't a valid password."
            validated = True
        if(txtPassword is not None and txtPassword != txtVerify):
            #self.response.out.write(inputForm % {"errorUsername":"", "errorPassword":"", "errorVerify":"Your passwords didn't match.","errorEmail":""})
            #self.response.out.write(printForm(VerifyError="Your passwords didn't match.", username=txtUsername, email=txtEmail))
            dict['VerifyError'] = "Your passwords didn't match."
            validated = True
        if(not verifyWithRegex(txtEmail, EMAIL_RE)):
            #self.response.out.write(inputForm % {"errorUsername":"", "errorPassword":"", "errorVerify":"","errorEmail":"That's not a valid email."})
            #self.response.out.write(printForm(EmailError="That's not a valid email.", username=txtUsername, email=txtEmail))
            dict['EmailError'] = "That's not a valid email."
            validated = True
        
        if (validated == None):
            self.redirect("/thanks")
        else:
            self.response.out.write(printForm(**dict))
            #self.response.out.write(printForm(UsernameError=usernameError, PasswordError =passwordError, VerifyError = verifyError, EmailError = emailError))

def verifyWithRegex(text, regexExpression):
    CORRECT_RE = re.compile(regexExpression)
    return CORRECT_RE.match(text)

def printForm(UsernameError = "", PasswordError ="", VerifyError = "", EmailError ="", Username ="", Email=""):
    newform = inputForm % {"errorUsername":UsernameError, "errorPassword":PasswordError, "errorVerify":VerifyError,"errorEmail":EmailError, "username":Username, "email":Email}
    return newform

    
app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/ROT13', EncodeHandler),
    ('/SignUp', SignUpHandler),
    ('/thanks', ThanksHandler)
], debug=True)

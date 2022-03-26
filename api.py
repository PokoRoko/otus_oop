#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import inspect
import json
import datetime
import logging
import hashlib
import uuid
from http import server, HTTPStatus
from optparse import OptionParser
from weakref import WeakKeyDictionary

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"

# Todo up to HTTPStatus
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class Field:
    def __init__(self, required=False, nullable=False):
        self.required = required
        self.nullable = nullable

    def check_constrains(self, value):
        if self.required and not value:
            raise ValueError(f"Field {self.__class__.__name__} is required")
        if self.nullable and not value:
            raise ValueError(f"Field {self.__class__.__name__} cannot be empty")


class CharField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.data = WeakKeyDictionary()

    def __get__(self, instance, owner):
        return self.data.get(instance)

    def __set__(self, instance, value):
        if type(value) not in (str, int):
            raise ValueError(f"Invalid value for {self.__class__.__name__}: {type(value).__name__}")
        self.data[instance] = value


class EmailField(CharField):
    def valid_field(self, value):
        if "@" not in value:
            raise ValueError(f"Invalid value for {self.__class__.__name__} don't have '@'")
        else:
            return True


class ArgumentsField(Field):
    def valid_field(self, value):
        try:
            json.dumps(value)
            return True
        except TypeError as e:
            err_msg = f"Invalid value for {self.__class__.__name__}, not JSON"
            logging.warning(err_msg)
            raise ValueError(err_msg)


class PhoneField(Field):
    def valid_field(self, value):
        err_msg = []
        if not type(value) in (str, int):
            err_msg.append(f"{self.__class__.__name__} must be a string or a number. Not {type(value)}")
        if not len(value) == 11:
            err_msg.append(f"{self.__class__.__name__} must be 11 digits long")
        if not str(value).startswith("7"):
            err_msg.append(f"{self.__class__.__name__} must start with the number 7")

        if len(err_msg) > 0:
            raise ValueError("\n".join(err_msg))
        else:
            return True


class DateField(Field):
    pass


class BirthDayField(Field):
    def valid_field(self, value):
        date = datetime.datetime.strptime(value, "%d.%m.%Y")
        delta = datetime.timedelta(days=(365 * 70))
        if datetime.datetime.now() - delta < date:
            return True
        else:
            raise ValueError(f"Invalid value for {self.__class__.__name__}, date > 70 year")


class GenderField(Field):
    pass


class ClientIDsField(Field):
    pass


class ClientsInterestsRequest(object):
    client_ids = ClientIDsField(required=True)
    date = DateField(nullable=True)


class OnlineScoreRequest(object):
    first_name = CharField(nullable=True)
    last_name = CharField(nullable=True)
    email = EmailField(nullable=True)
    phone = PhoneField(nullable=True)
    birthday = BirthDayField(nullable=True)
    gender = GenderField(nullable=True)


class MethodRequest(object):
    account = CharField(nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True)

    def __init__(self, request):
        self.request = request

    def get_response(self):
        return None, None

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    else:
        digest = hashlib.sha512(request.account + request.login + SALT).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    auth = check_auth(request)
    methode_request = MethodRequest(request)
    response, code = methode_request.get_response()
    return response, code


class MainHTTPHandler(server.BaseHTTPRequestHandler):
    router = {
        "online_score": method_handler,
        "clients_interests": method_handler,
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode())
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = server.HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import hashlib
import json
import logging
import uuid
from http import HTTPStatus, server
from optparse import OptionParser
from weakref import WeakKeyDictionary

from scoring import get_interests, get_score

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"

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


class CharField(Field):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.data = WeakKeyDictionary()

    def __get__(self, instance, owner):
        return self.data.get(instance)

    def __set__(self, instance, value):
        self.check_constrains(value)
        if self.nullable and not value:
            self.data[instance] = ''
        else:
            self.valid_field(value)

        if type(value) not in (str, int, dict):
            raise ValueError(f"Invalid value for {self.__class__.__name__}: {type(value).__name__}")
        else:
            self.data[instance] = value

    def check_constrains(self, value):
        if self.required and not value:
            raise ValueError(f"Field {self.__class__.__name__} is required")
        if not self.nullable and not value:
            raise ValueError(f"Field {self.__class__.__name__} cannot be empty")

    @staticmethod
    def valid_field(value):
        pass


class EmailField(CharField):
    def valid_field(self, value):
        if "@" not in value:
            raise ValueError(f"Invalid value for {self.__class__.__name__} don't have '@'")
        else:
            return True


class ArgumentsField(CharField):
    def valid_field(self, value):
        try:
            json.dumps(value)
            return True
        except TypeError as error:
            err_msg = f"Invalid value for {self.__class__.__name__}, not JSON"
            logging.warning(err_msg + str(error))
            raise ValueError(err_msg)


class PhoneField(CharField):
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


class DateField(CharField):
    def valid_field(self, value):
        try:
            _ = datetime.datetime.strptime(value, "%d.%m.%Y")
            return True
        except ValueError:
            raise ValueError(f"{self.__class__.__name__} {value} does not match format '%d.%m.%Y'")


class BirthDayField(CharField):
    def valid_field(self, value):
        try:
            date = datetime.datetime.strptime(value, "%d.%m.%Y")
            delta = datetime.timedelta(days=(365 * 70))
        except ValueError:
            raise ValueError(f"{self.__class__.__name__} {value} does not match format '%d.%m.")

        if datetime.datetime.now() - delta < date:
            return True
        else:
            raise ValueError(f"Invalid value for {self.__class__.__name__}, date > 70 year")


class GenderField(CharField):
    def valid_field(self, value):
        if value not in (0, 1, 2):
            raise ValueError(f"Invalid value for {self.__class__.__name__} can only be 0 or 1 or 2")
        else:
            return True


class ClientIDsField(CharField):
    def valid_field(self, value):
        try:
            ids_tuple = set(value)
            sum(ids_tuple)
        except TypeError:
            raise TypeError(f"list {self.__class__.__name__} can include only integers")


class MethodRequest(object):
    account = CharField(nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True)

    def __init__(self, **kwargs):
        self.account = kwargs.get('account')
        self.login = kwargs.get('login')
        self.token = kwargs.get('token')
        self.arguments = kwargs.get('arguments')
        self.method = kwargs.get('method')

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


class ClientsInterestsRequest(MethodRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(nullable=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.client_ids = self.arguments.get("client_ids")
        self.date = self.arguments.get("date")

    def get_response(self):
        res = {}
        for cid in self.arguments.get("client_ids"):
            res[cid] = get_interests(store=None, cid=cid)
        return res, HTTPStatus.OK


class OnlineScoreRequest(MethodRequest):
    first_name = CharField(nullable=True)
    last_name = CharField(nullable=True)
    email = EmailField(nullable=True)
    phone = PhoneField(nullable=True)
    birthday = BirthDayField(nullable=True)
    gender = GenderField(nullable=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.first_name = self.arguments.get("first_name")
        self.last_name = self.arguments.get("last_name")
        self.email = self.arguments.get("email")
        self.phone = self.arguments.get("phone")
        self.birthday = self.arguments.get("birthday")
        self.gender = self.arguments.get("gender")
        self._valid_request()

    def _valid_request(self):
        """
        ?????????????????? ??????????????, ???????? ?????????????? ?????? ???????? ???? ?????????????????????? ?? ???????? ?????????????????????? ???????? ???????? ????????
        phone-email, first name-last name, gender-birthday ?? ?????????????????? ????????????????????.
        """
        valid_pairs = any([
            all([self.first_name, self.last_name]),
            all([self.email, self.phone]),
            all([self.birthday, self.gender])
        ])
        if not valid_pairs:
            raise ValueError(f"Invalid request {self.__class__.__name__} must be at least one pair"
                             f"(phone-email) or (first name-last name) or (gender-birthday)")

    def get_response(self):
        if self.is_admin:
            res = 42
        else:
            res = get_score(store=None, **self.arguments)
        return res, HTTPStatus.OK


def check_auth(request):
    if request.is_admin:
        to_hash = datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT
    else:
        to_hash = request.account + request.login + SALT

    digest = hashlib.sha512(to_hash.encode()).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    request_method = request["body"].get("method")
    supported_requests = {
        "online_score": OnlineScoreRequest,
        "clients_interests": ClientsInterestsRequest,
    }

    if request_method in supported_requests:
        try:
            methode_request = supported_requests[request_method](**request["body"])
        except (ValueError, TypeError) as error:
            return str(error), HTTPStatus.UNPROCESSABLE_ENTITY

    else:
        return f"Unsupported method: {request_method}", HTTPStatus.METHOD_NOT_ALLOWED

    auth = check_auth(methode_request)
    if not auth:
        response = "Forbidden"
        code = HTTPStatus.FORBIDDEN
    else:
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
        response, code = {}, HTTPStatus.OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except Exception as error:
            logging.warning(f"BAD_REQUEST ERROR: {error}")
            code = HTTPStatus.BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = HTTPStatus.INTERNAL_SERVER_ERROR
            else:
                code = HTTPStatus.NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        if code in [HTTPStatus.OK]:
            r = {"response": response, "code": code}
        else:
            r = {"error": response, "code": code}
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
                        format='[%(asctime)s] %(levelname)s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = server.HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()

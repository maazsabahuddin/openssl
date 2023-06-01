"""
This script sent an email about the certificate expiration.
Author: Maaz Sabah Uddin
"""

# Python Imports
import socket
import ipaddress
import threading
import ssl
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from io import BytesIO
from datetime import datetime

# Local Imports
from logging_config import logger
import config
import enums

# Framework Imports
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter


class SSLConnection:

    networks = None
    port = 443
    timeout = 1
    active_hosts = []

    def __init__(self, nws, port=443):
        self.networks = nws
        self.port = port

    def check_port(self, host):
        """
        This function is to check whether the host is listening on a port 443.
        :param host:
        :return:
        """
        try:
            if socket.create_connection((host, self.port), timeout=self.timeout):
                logger.info(f"Host: {host}")
                self.active_hosts.append(str(host))
        except (socket.error, socket.timeout, ConnectionRefusedError):
            pass

    @staticmethod
    def split_network(nw, prefix_length=26):
        """
        This function split the network into smaller subnets
        :param nw: nw is Network
        :param prefix_length:
        :return:
        """
        return list(ipaddress.ip_network(nw).subnets(new_prefix=prefix_length))

    def scan_subnet(self, subnet):
        """
        This function will scan and check port 443 on each host of a subnet.
        Also, this function is to scan each subnet concurrently.
        :param subnet:
        :return:
        """
        [threading.Thread(target=self.check_port, args=(str(host),)).start() for host in list(subnet.hosts())]

    @staticmethod
    def is_private_network(nw):
        try:
            ip_obj = ipaddress.ip_address(nw.split('/')[0])
            return ip_obj.is_private
        except ValueError:
            return False

    def get_all_network_with_subnets(self):
        """
        This function will return all the networks public and private networks within the SNOLAB.
        :return:
        """
        return [subnet for nw in self.networks if SSLConnection.is_private_network(nw) for subnet in
                SSLConnection.split_network(nw=nw)] + [ipaddress.ip_network(nw) for nw in self.networks if
                                                       not SSLConnection.is_private_network(nw)]

    def get_active_hosts(self):
        """
        This function will return all the active hosts that are listening on port 443 with in the SNOLAB Public
        and Private networks.
        :return:
        """

        _ = [thread.start() or thread.join()
             for thread in [threading.Thread(target=self.scan_subnet, args=(subnet,))
                            for subnet in self.get_all_network_with_subnets()]]

        return self.active_hosts


class SnolabNetwork:

    port = 443
    timeout = 0.1
    certificates_information = {}

    def get_certificate_info(self, ip_address, port=443):
        """
        This function will return the certificate information of the host on 443 port.
        :param ip_address:
        :param port:
        :return:
        """
        host = self.get_domain_name(ip_address=ip_address)
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    return cert, None
        # except ssl.SSLCertVerificationError as err:
        #     return None, err
        except (ssl.SSLError, ssl.SSLCertVerificationError) as err:
            return None, {'obj': err, 'type': 'SSL'}
        except (ConnectionRefusedError, TimeoutError, FileNotFoundError, socket.gaierror, Exception) as err:
            return None, {'obj': err, 'type': 'General'}

    @staticmethod
    def convert_tuple_into_dict(_tuple):
        """
        This function will take tuple into dictionary and return a dict.
        :param _tuple:
        :return:
        """
        return dict((x, y) for index in _tuple for x, y in index)

    @staticmethod
    def convert_string_date_to_date_format(_date: str):
        """
        This function converts the string date into date format
        :param _date:
        :return:
        """
        return datetime.strptime(_date, '%b %d %H:%M:%S %Y %Z').date()

    def update_certificate_groups(self, hosts, certificate_groups):
        """
        This function will update different types of certificates on reference.
        :param hosts:
        :param certificate_groups:
        :return:
        """
        today_date = datetime.today().date()
        for host in hosts:
            logger.info(f"Fetching Certificates for host {host}")
            cert_info, error = self.get_certificate_info(host)
            if cert_info is not None:
                cert_info['host'] = host
                cert_info['issuer'] = SnolabNetwork.convert_tuple_into_dict(_tuple=cert_info['issuer'])
                cert_info['subject'] = SnolabNetwork.convert_tuple_into_dict(_tuple=cert_info['subject'])
                certificate_expiring_date = SnolabNetwork.convert_string_date_to_date_format(
                    _date=cert_info['notAfter'])
                cert_expiring_days = (certificate_expiring_date - today_date).days

                cert_info['expiring_in'] = cert_expiring_days
                if cert_expiring_days <= 7:
                    certificate_groups['expiring_soon_7certificates'].append(cert_info)
                elif cert_expiring_days <= 15:
                    certificate_groups['expiring_soon_15certificates'].append(cert_info)
                elif cert_expiring_days <= 30:
                    certificate_groups['expiring_soon_30certificates'].append(cert_info)
                elif cert_expiring_days <= 45:
                    certificate_groups['expiring_soon_45certificates'].append(cert_info)
                certificate_groups['active_certificates'].append(cert_info)
            else:
                certificate_groups['exception_certificates'].append(error) if error['type'] != "SSL" \
                    else certificate_groups['expired_certificates'].append(error) \
                    if error['obj'].reason == "CERTIFICATE_VERIFY_FAILED" and error['obj'].verify_code == 10 \
                    else certificate_groups['exception_certificates'].append(error)

        self.certificates_information.update(certificate_groups)

    def fetch_certificates(self, hosts):
        """
        This function will fetch host certificate info if there is no exception.
        :param hosts:
        :return:
        """
        logger.info("Fetching Certificates on each host throughout the network.")
        certificate_groups = {
            'active_certificates': [],
            'expired_certificates': [],
            'expiring_soon_45certificates': [],
            'expiring_soon_30certificates': [],
            'expiring_soon_15certificates': [],
            'expiring_soon_7certificates': [],
            'exception_certificates': []
        }

        self.update_certificate_groups(hosts=hosts, certificate_groups=certificate_groups)
        return self.certificates_information

    @staticmethod
    def get_domain_name(ip_address):
        """
        This function will return the domain name if attached with the ip address.
        :param ip_address:
        :return:
        """
        try:
            domain_name = socket.gethostbyaddr(ip_address)[0]
            return domain_name
        except socket.herror:
            return None

    @staticmethod
    def get_email_body():
        """
        This function will return the body of the email
        :return:
        """
        return "Please find the attached PDF report that shows which certificates are expiring.\n\n" \
               f"The report specifically focuses on the following networks: {config.SNOLAB_NETWORKS}\n\n" \
               "Please note that this is an automated email. Please DO NOT reply to this email."

    @staticmethod
    def get_email_subject(cert_info):
        """
        This function will return the subject for the email
        :param cert_info:
        :return:
        """
        n = 7 if len(cert_info[f'expiring_soon_{7}certificates']) > 0 \
            else 15 if len(cert_info[f'expiring_soon_{15}certificates']) > 0 \
            else 30 if len(cert_info[f'expiring_soon_{30}certificates']) > 0 \
            else 45 if len(cert_info[f'expiring_soon_{45}certificates']) > 0 \
            else None

        return "Cheers! No certificates are expiring within 45 days." if not n else \
            f"Alert! Certificates are expiring in the next {n} days."

    def generate_report(self):
        """
        This function will generate the report based on the data.
        :return:
        """
        buffer = BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        report_obj = Report(p=p)
        report_obj.design_header(date=datetime.today().date())
        report_obj.design_body(data=self.certificates_information)
        report_obj.design_footer()
        report_obj.save_report()
        buffer.seek(0)

        Email(buf=buffer).send_email(sender=config.EMAIL_USERNAME, receiver=config.EMAIL_SENT_TO,
                                     subject=SnolabNetwork.get_email_subject(cert_info=self.certificates_information),
                                     body=SnolabNetwork.get_email_body())


class Report:

    p = None
    page_counter = 0

    def __init__(self, p):
        self.p = p

    def design_header(self, date):
        """
        This function is responsible to design header of the Emanation Result report.
        :param date:
        :return:
        """

        logo_path = 'images/SNOLAB-logo.png'  # Replace with the actual path to your logo file
        self.p.drawImage(logo_path, 50, 720, 80, 50)  # Adjust x, y, width, height as needed

        # Draw the horizontal line
        self.p.line(20, 700, 592, 700)

        # Set header
        self.p.setFont("Helvetica-Bold", enums.Report.HEADER_FONT_SIZE)
        self.p.drawString(190, 730, "Expiring Certificates Report")

        self.p.setFont("Helvetica", enums.Report.BODY_FONT_SIZE)
        self.p.drawString(470, 730, f"Date: {date}")

    def design_body(self, data):
        """
        This function will generate the body for the report.
        :param data:
        :return:
        """
        self.certificates_expiring_in_n_days(certificates=data[f'expiring_soon_{7}certificates'], n=7)
        self.certificates_expiring_in_n_days(certificates=data[f'expiring_soon_{15}certificates'], n=15,
                                             second_page=True)
        self.certificates_expiring_in_n_days(certificates=data[f'expiring_soon_{30}certificates'], n=30,
                                             second_page=True)
        self.certificates_expiring_in_n_days(certificates=data[f'expiring_soon_{45}certificates'], n=45,
                                             second_page=True, is_last=True)

    def design_footer(self):
        """
        This function is responsible to design footer for the report.
        :return:
        """

        # Draw the horizontal line
        self.p.line(20, 35, 592, 35)

        # Set footer
        self.p.setFont("Helvetica", enums.Report.FOOTER_FONT_SIZE)
        self.p.drawString(enums.Report.X_AXIS_START_POINT, 15,
                          f"Copyright {datetime.today().date().year} SNOLAB. All rights reserved")
        self.page_counter += 1
        self.p.drawString(540, 15, f"Page {self.page_counter}")

    def certificates_expiring_in_n_days(self, certificates, n: int, second_page=False, is_last=False):
        """
        This function will update the body for the certificates expiring in n days.
        :param certificates:
        :param n:
        :param second_page:
        :param is_last:
        :return:
        """
        # Set body header
        self.p.setFont("Helvetica-Bold", enums.Report.HEADER_FONT_SIZE)
        y_axis_initial_length = enums.Report.Y_AXIS_INITIAL_LENGTH \
            if not second_page else enums.Report.Y_AXIS_INITIAL_LENGTH + 50
        self.p.drawString(enums.Report.X_AXIS_START_POINT, y_axis_initial_length, f"Certificates Expiring in {n} days")

        # Setting body font
        self.p.setFont("Helvetica", enums.Report.BODY_FONT_SIZE)

        y_axis_initial_length -= (enums.Report.Y_AXIS_INITIAL_DIFFERENCE * 2)

        if len(certificates) < 1:
            self.p.drawString(enums.Report.X_AXIS_START_POINT, y_axis_initial_length,
                              f"No certificates are expiring in the next {n} days.")
        else:
            for exp_cert in certificates:

                if y_axis_initial_length - 35 < 60:
                    self.design_footer()
                    self.p.showPage()
                    y_axis_initial_length = enums.Report.Y_AXIS_INITIAL_LENGTH + 50

                self.p.drawString(enums.Report.X_AXIS_START_POINT, y_axis_initial_length,
                                  f"Host {exp_cert['subject']['commonName']} ({exp_cert['host']})")

                y_axis_initial_length -= enums.Report.Y_AXIS_INITIAL_DIFFERENCE
                self.p.drawString(enums.Report.X_AXIS_START_POINT, y_axis_initial_length,
                                  f"Issuer {exp_cert['issuer']['organizationName']}")

                y_axis_initial_length -= enums.Report.Y_AXIS_INITIAL_DIFFERENCE
                self.p.drawString(enums.Report.X_AXIS_START_POINT, y_axis_initial_length,
                                  f"Expiring On {exp_cert['notAfter']}")

                y_axis_initial_length -= enums.Report.Y_AXIS_INITIAL_DIFFERENCE
                self.p.drawString(enums.Report.X_AXIS_START_POINT, y_axis_initial_length,
                                  f"Days Remaining {exp_cert['expiring_in']} days")

                y_axis_initial_length -= (enums.Report.Y_AXIS_INITIAL_DIFFERENCE * 2)

        if not is_last:
            self.design_footer()
            self.p.showPage()

    def save_report(self):
        """
        This function will save the report
        :return:
        """
        self.p.save()


class Email:

    # Email configuration
    buffer = None
    smtp_server = config.SMTP_SERVER
    smtp_port = config.SMTP_PORT
    username = config.EMAIL_USERNAME
    password = config.EMAIL_PASSWORD

    def __init__(self, buf):
        self.buffer = buf

    def send_email(self, sender, receiver, subject, body):
        """
        This function will email to the specified receiver.
        :param sender:
        :param receiver:
        :param subject:
        :param body:
        :return:
        """
        # Create the email message
        message = MIMEMultipart()
        message["Subject"] = subject
        message["From"] = sender
        message["To"] = receiver

        message.attach(MIMEText(body))

        attachment = MIMEApplication(self.buffer.read(), _subtype="pdf")
        attachment.add_header("Content-Disposition", "attachment",
                              filename=f"expiring-certificates-{datetime.today().date()}.pdf")
        message.attach(attachment)

        # Send the email
        with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
            server.starttls()
            server.login(self.username, self.password)
            server.send_message(message)


if __name__ == '__main__':

    ssl_conn = SSLConnection(nws=config.SNOLAB_NETWORKS)
    # Retrieve all the active hosts of the SNOLAB Public and Private Network
    active_hosts = ssl_conn.get_active_hosts()

    sn = SnolabNetwork()
    # Fetch all the certificates that are expired
    sn.fetch_certificates(hosts=active_hosts)

    # and then generate a report based on it.
    sn.generate_report()

"""
This script sent an email about the certificate expiration.
Author: Maaz Sabah Uddin
"""

# Python Imports
import sys
import socket
import time
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
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from cryptography import x509
from cryptography.hazmat.backends import default_backend

if sys.platform.startswith('linux'):
    config.increase_file_descriptor_limit()


def error_handler(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.exception(f"Error: {e}")
    return wrapper


class SSLConnection:

    networks = None
    port = 443
    timeout = 1
    active_hosts = []

    def __init__(self, nws, port=443):
        self.networks = nws
        self.port = port

    def check_port(self, host, port=None):
        """
        This function is to check whether the host is listening on a port default 443.
        :param host:
        :param port:
        :return:
        """
        try:
            _port = self.port if not port else port
            with socket.create_connection((host, _port), timeout=self.timeout):
                logger.info(f"Host: {host} - Port {_port}")
                self.active_hosts.append(f"{host}/{_port}")
        except (socket.error, socket.timeout, ConnectionRefusedError, Exception) as e:
            pass

    @staticmethod
    def split_network(nw, prefix_length=24):
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
        return [ipaddress.ip_network(nw) for nw in self.networks if not SSLConnection.is_private_network(nw)] + \
            [subnet for nw in self.networks if SSLConnection.is_private_network(nw)
             for subnet in SSLConnection.split_network(nw=nw)]

    def get_active_hosts(self):
        """
        This function will return all the active hosts that are listening on port 443 with in the SNOLAB Public
        and Private networks.
        :return:
        """
        for subnet in self.get_all_network_with_subnets():
            self.scan_subnet(subnet)

        for _ in config.CUSTOM_HOSTS_TO_SCAN:
            host, port = _.split('/')
            self.check_port(host=host, port=port)

        # Below code is the shorter code with same functionality
        # _ = [thread.start() or thread.join()
        #      for thread in [threading.Thread(target=self.scan_subnet, args=(subnet,))
        #                     for subnet in self.get_all_network_with_subnets()]]

        return self.active_hosts


class SnolabNetwork:

    port = 443
    timeout = 0.1
    certificates_information = {}

    @staticmethod
    def parse_certificate(cert_bytes):
        """
        This function is going to parse the certificate based on the requirements
        :param cert_bytes:
        :return:
        """

        # Converting bytes to dict
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())

        # Fetching subject attributes
        subject_attributes = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        subject = {attr.oid._name: attr.value for attr in subject_attributes}

        # Fetching issuer attributes
        issuer_attributes = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        issuer = {attr.oid._name: attr.value for attr in issuer_attributes}
        issuer_org_attributes = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
        issuer["organizationName"] = issuer_org_attributes[0].value if issuer_org_attributes else ""

        validity = {
            "notBefore": cert.not_valid_before,
            "notAfter": cert.not_valid_after
        }

        certificate_info = {
            "subject": subject,
            "issuer": issuer,
            "validity": validity,
        }

        return certificate_info

    def get_certificate_info(self, ip_address):
        """
        This function will return the certificate information of the host on 443 port.
        :param ip_address:
        :return:
        """
        ip_address, port = ip_address.split('/')
        host = self.get_domain_name(ip_address=ip_address)
        try:
            context = ssl.create_default_context()
            context.check_hostname = False  # Disable hostname verification
            context.verify_mode = ssl.CERT_NONE  # Disable certificate verification
            with socket.create_connection((ip_address, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip_address) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    return SnolabNetwork.parse_certificate(cert), None
        except (ssl.SSLError, ssl.SSLCertVerificationError) as err:
            return None, {'obj': err, 'type': 'SSL', 'hostname': host, 'host': f"{ip_address}/{port}"}
        except (ConnectionRefusedError, TimeoutError, FileNotFoundError, socket.gaierror, Exception) as err:
            return None, {'obj': err, 'type': 'General', 'hostname': host, 'host': f"{ip_address}/{port}"}

    def update_certificate_groups(self, host, certificate_groups):
        """
        This function will update different types of certificates on reference.
        :param host:
        :param certificate_groups:
        :return:
        """
        today_date = datetime.today().date()
        logger.info(f"Fetching Certificates for host {host}")
        cert_info, error = self.get_certificate_info(host)
        if cert_info is not None:
            cert_info['host'] = host
            certificate_expiring_date = cert_info['validity']['notAfter'].date()
            cert_expiring_days = (certificate_expiring_date - today_date).days

            cert_info['expiring_in'] = cert_expiring_days
            if cert_expiring_days < 0:
                cert_info['expiring_in'] = abs(cert_info['expiring_in'])
                _message = f"The certificate expired on {certificate_expiring_date} " \
                           f"({cert_info['expiring_in']} days ago)."
                cert_info['obj'] = _message
                cert_info['hostname'] = cert_info['subject']['commonName']
                certificate_groups['expired_certificates'].append(cert_info)
            elif cert_expiring_days <= 7:
                certificate_groups['expiring_soon_7certificates'].append(cert_info)
            elif cert_expiring_days <= 15:
                certificate_groups['expiring_soon_15certificates'].append(cert_info)
            elif cert_expiring_days <= 30:
                certificate_groups['expiring_soon_30certificates'].append(cert_info)
            elif cert_expiring_days <= 45:
                certificate_groups['expiring_soon_45certificates'].append(cert_info)
            else:
                certificate_groups['expiring_soon_365certificates'].append(cert_info)
        else:
            certificate_groups['exception_certificates'].append(error)
            error['obj'] = str(error['obj'])

        self.certificates_information.update(certificate_groups)

    def fetch_certificates(self, hosts):
        """
        This function will fetch host certificate info if there is no exception.
        :param hosts:
        :return:
        """
        logger.info("Fetching Certificates on each host throughout the network.")
        certificate_groups = {
            'expired_certificates': [],
            'expiring_soon_365certificates': [],
            'expiring_soon_45certificates': [],
            'expiring_soon_30certificates': [],
            'expiring_soon_15certificates': [],
            'expiring_soon_7certificates': [],
            'exception_certificates': []
        }

        for host in hosts:
            self.update_certificate_groups(host=host, certificate_groups=certificate_groups)

        logger.info("Fetching certificates information completed.")
        self.sort_certs()
        return self.certificates_information

    def sort_certs(self):
        """
        This function will be responsible to sort the certificates based on their expiry.
        :return:
        """
        logger.info("Sorting certificates")
        self.certificates_information['expiring_soon_365certificates'] = \
            sorted(self.certificates_information['expiring_soon_365certificates'],
                   key=lambda d: d.get('expiring_in', float('inf')))

        self.certificates_information['expiring_soon_45certificates'] = \
            sorted(self.certificates_information['expiring_soon_45certificates'],
                   key=lambda d: d.get('expiring_in', float('inf')))

        self.certificates_information['expiring_soon_30certificates'] = \
            sorted(self.certificates_information['expiring_soon_30certificates'],
                   key=lambda d: d.get('expiring_in', float('inf')))

        self.certificates_information['expiring_soon_15certificates'] = \
            sorted(self.certificates_information['expiring_soon_15certificates'],
                   key=lambda d: d.get('expiring_in', float('inf')))

        self.certificates_information['expiring_soon_7certificates'] = \
            sorted(self.certificates_information['expiring_soon_7certificates'],
                   key=lambda d: d.get('expiring_in', float('inf')))

        self.certificates_information['expired_certificates'] = \
            sorted(self.certificates_information['expired_certificates'],
                   key=lambda d: d.get('expiring_in', float('inf')))

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
            return ""

    @staticmethod
    def get_email_body():
        """
        This function will return the body of the email
        :return:
        """
        networks_hosts = config.SNOLAB_NETWORKS + config.CUSTOM_HOSTS_TO_SCAN
        return "Please find the attached PDF report that shows which certificates are expiring.\n\n" \
               f"The report specifically focuses on the following networks: {networks_hosts}\n\n" \
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

    @error_handler
    def generate_report_and_send_email(self):
        """
        This function will generate the report based on the data and send the report ot the user.
        :return:
        """
        attachments = [Report().generate_expiring_soon_certificate_report(
            certificates_information=self.certificates_information)
        ]

        if get_all_certificates_info():
            attachments.append(Report().generate_all_certificates_report(
                certificates_information=self.certificates_information)
            )

        logger.info(f"Sending email to: {config.EMAIL_SENT_TO}")
        Email(pdfs=attachments)\
            .send_email(sender=config.EMAIL_USERNAME,
                        receiver=config.EMAIL_SENT_TO,
                        subject=SnolabNetwork.get_email_subject(cert_info=self.certificates_information),
                        body=SnolabNetwork.get_email_body())
        logger.info(f"Email successfully sent.")


class Report:

    page_counter = 0

    def __init__(self):
        pass

    @staticmethod
    def design_header(p, heading):
        """
        This function is responsible to design header of the Emanation Result report.
        :param p:
        :param heading:
        :return:
        """
        date = datetime.today().date()

        # Adjust x, y, width, height as needed
        p.drawImage(ImageReader(config.REPORT_LOGO_DATA), 50, 720, 80, 50)

        # Draw the horizontal line
        p.line(20, 700, 592, 700)

        # Set header
        p.setFont("Helvetica-Bold", enums.Report.HEADER_FONT_SIZE)
        p.drawString(150, 730, f"{heading}")

        p.setFont("Helvetica", enums.Report.BODY_FONT_SIZE)
        p.drawString(470, 730, f"Date: {date}")

    def design_body(self, p, data, regular=True):
        """
        This function will generate the body for the report.
        :param p:
        :param data:
        :param regular:
        :return:
        """
        if not regular:
            self.generate_all_certs_body(p=p, certificates=data['expired_certificates']+data['exception_certificates'])
        else:
            self.certificates_expiring_in_n_days(p=p, certificates=data[f'expiring_soon_{7}certificates'], n=7)
            self.certificates_expiring_in_n_days(p=p, certificates=data[f'expiring_soon_{15}certificates'], n=15,
                                                 second_page=True)
            self.certificates_expiring_in_n_days(p=p, certificates=data[f'expiring_soon_{30}certificates'], n=30,
                                                 second_page=True)
            self.certificates_expiring_in_n_days(p=p, certificates=data[f'expiring_soon_{45}certificates'], n=45,
                                                 second_page=True)
            self.certificates_expiring_in_n_days(p=p, certificates=data[f'expiring_soon_{365}certificates'], n=365,
                                                 second_page=True, is_last=True)

    def design_footer(self, p):
        """
        This function is responsible to design footer for the report.
        :return:
        """

        # Draw the horizontal line
        p.line(20, 35, 592, 35)

        # Set footer
        p.setFont("Helvetica", enums.Report.FOOTER_FONT_SIZE)
        p.drawString(enums.Report.X_AXIS_START_POINT, 15,
                     f"Copyright {datetime.today().date().year} SNOLAB. All rights reserved")
        self.page_counter += 1
        p.drawString(540, 15, f"Page {self.page_counter}")

    def generate_all_certs_body(self, p, certificates):
        """
        This function will generate the all certificates body.
        :param p:
        :param certificates:
        :return:
        """
        y_axis_initial_length = enums.Report.Y_AXIS_INITIAL_LENGTH

        for cert in certificates:

            if y_axis_initial_length - 35 < 60:
                self.design_footer(p=p)
                p.showPage()
                y_axis_initial_length = enums.Report.Y_AXIS_INITIAL_LENGTH + 50

            p.drawString(enums.Report.X_AXIS_START_POINT, y_axis_initial_length,
                         f"Host {cert['hostname']} ({cert['host']})")
            y_axis_initial_length -= enums.Report.Y_AXIS_INITIAL_DIFFERENCE
            if len(cert['obj']) > 85:
                error_obj = cert['obj'].split(']')
                p.drawString(enums.Report.X_AXIS_START_POINT, y_axis_initial_length, f"Error {error_obj[0]}")
                y_axis_initial_length -= enums.Report.Y_AXIS_INITIAL_DIFFERENCE
                p.drawString(enums.Report.X_AXIS_START_POINT, y_axis_initial_length, f"{error_obj[1]}")
            else:
                p.drawString(enums.Report.X_AXIS_START_POINT, y_axis_initial_length, f"Error {cert['obj']}")

            y_axis_initial_length -= (enums.Report.Y_AXIS_INITIAL_DIFFERENCE * 2)

    def certificates_expiring_in_n_days(self, p, certificates, n: int, second_page=False, is_last=False):
        """
        This function will update the body for the certificates expiring in n days.
        :param p:
        :param certificates:
        :param n:
        :param second_page:
        :param is_last:
        :return:
        """
        # Set body header
        p.setFont("Helvetica-Bold", enums.Report.HEADER_FONT_SIZE)
        y_axis_initial_length = enums.Report.Y_AXIS_INITIAL_LENGTH \
            if not second_page else enums.Report.Y_AXIS_INITIAL_LENGTH + 50

        _msg = f"Certificates Expiring in {n}"
        if n == 365:
            _msg = f"Certificates Expiring in {n} days or more"
        p.drawString(enums.Report.X_AXIS_START_POINT, y_axis_initial_length, _msg)

        # Setting body font
        p.setFont("Helvetica", enums.Report.BODY_FONT_SIZE)

        y_axis_initial_length -= (enums.Report.Y_AXIS_INITIAL_DIFFERENCE * 2)

        if len(certificates) < 1:
            p.drawString(enums.Report.X_AXIS_START_POINT, y_axis_initial_length,
                         f"No certificates are expiring in the next {n} days.")
        else:
            for exp_cert in certificates:

                if y_axis_initial_length - 35 < 60:
                    self.design_footer(p=p)
                    p.showPage()
                    y_axis_initial_length = enums.Report.Y_AXIS_INITIAL_LENGTH + 50

                p.drawString(enums.Report.X_AXIS_START_POINT, y_axis_initial_length,
                             f"Host {exp_cert['subject'].get('commonName', '')} ({exp_cert['host']})")

                y_axis_initial_length -= enums.Report.Y_AXIS_INITIAL_DIFFERENCE
                p.drawString(enums.Report.X_AXIS_START_POINT, y_axis_initial_length,
                             f"Issuer {exp_cert['issuer']['organizationName']}")

                y_axis_initial_length -= enums.Report.Y_AXIS_INITIAL_DIFFERENCE
                p.drawString(enums.Report.X_AXIS_START_POINT, y_axis_initial_length,
                             f"Expiring On {exp_cert['validity']['notAfter']}")

                y_axis_initial_length -= enums.Report.Y_AXIS_INITIAL_DIFFERENCE
                p.drawString(enums.Report.X_AXIS_START_POINT, y_axis_initial_length,
                             f"Days Remaining {exp_cert['expiring_in']} days")

                y_axis_initial_length -= (enums.Report.Y_AXIS_INITIAL_DIFFERENCE * 2)

        if not is_last:
            self.design_footer(p=p)
            p.showPage()

    def generate_expiring_soon_certificate_report(self, certificates_information):
        """
        This function will generate the expiring soon report.
        :param certificates_information:
        :return:
        """
        logger.info("Generating the expiring soon report")
        buffer = BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        Report.design_header(p=p, heading="Certificates Expiring Soon Report")
        self.design_body(p=p, data=certificates_information)
        self.design_footer(p=p)
        logger.info("Saving the report")
        Report.save_report(p=p)
        buffer.seek(0)

        return {'value': buffer.getvalue(), 'name': f"certs-expiring-soon-report.pdf"}

    def generate_all_certificates_report(self, certificates_information):
        """
        This function will return the information for all the certificates.
        :param certificates_information:
        :return:
        """
        logger.info("Generating all certificates report including expired and exception.")
        buffer = BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        Report.design_header(p=p, heading="Certificates with Exception Report")
        self.design_body(p=p, data=certificates_information, regular=False)
        self.design_footer(p=p)
        logger.info("Saving the report")
        Report.save_report(p=p)
        buffer.seek(0)

        return {'value': buffer.getvalue(), 'name': f"all-certs-report.pdf"}

    @staticmethod
    def save_report(p):
        """
        This function will save the report.
        :param p:
        :return:
        """
        p.save()


class Email:

    # Email configuration
    smtp_server = config.SMTP_SERVER
    smtp_port = config.SMTP_PORT
    username = config.EMAIL_USERNAME

    def __init__(self, pdfs):
        self.pdfs = pdfs

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

        for pdf in self.pdfs:
            attachment = MIMEApplication(pdf['value'], _subtype="pdf")
            attachment.add_header("Content-Disposition", "attachment", filename=pdf['name'])
            message.attach(attachment)

        with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
            # Send the email
            server.sendmail(message["From"], message["To"], message.as_string())
            # Close the connection to the SMTP server
            server.quit()


def get_arguments():
    """
    This function will retrieve all the command line arguments.
    :return:
    """
    import sys
    return sys.argv


def get_all_certificates_info():
    """
    This function will return a boolean value based on the arguments provided while running the script.
    :return:
    """
    args = get_arguments()
    if len(args) < 2:
        return False or True
    return args[1] == "--all" or True


if __name__ == '__main__':

    # Start time
    start_time = time.time()

    # Retrieve all the active hosts of the SNOLAB Public and Private Network
    ssl_conn = SSLConnection(nws=config.SNOLAB_NETWORKS)
    active_hosts = ssl_conn.get_active_hosts()

    # Fetch all the certificates that are expired
    sn = SnolabNetwork()

    # Fetching certificates
    sn.fetch_certificates(hosts=active_hosts)

    # Generate the report and send the email.
    sn.generate_report_and_send_email()

    # End time
    end_time = time.time()

    # Print the elapsed time in seconds
    logger.info(f"Elapsed time: {end_time - start_time} seconds")
    sys.exit(0)

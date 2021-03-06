Designate, a DNSaaS component for OpenStack
===========================================

Designate provides DNSaaS services for OpenStack:

* REST API for domain & record management
* Multi-tenant
* Integrated with Keystone for authentication
* Framework in place to integrate with Nova and Neutron notifications (for auto-generated records)
* Support for PowerDNS and Bind9 out of the box

This document describes Designate for users & contributors of the project.

This documentation is generated by the Sphinx toolkit and lives in the `source tree`_. Additional documentation on Designate may
also be found on the `OpenStack wiki`_.

Install Guides
==============

.. toctree::
    :maxdepth: 1
    :glob:

    install/*

How To Guides
=============

.. toctree::
    :maxdepth: 1
    :glob:

    howtos/*

Reference Documentation
=======================

.. toctree::
   :maxdepth: 1

   architecture
   getting-involved
   developer-guidelines
   production-guidelines
   production-architecture
   configuration
   rest
   devstack
   related
   glossary
   backends
   integrations
   functional-tests
   gmr
   support-matrix

Source Documentation
====================

.. toctree::
    :maxdepth: 3

    api
    backend
    central
    mdns
    objects
    quota
    sink
    storage

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`



.. _OpenStack Wiki: https://wiki.openstack.org/wiki/Designate
.. _source tree: https://github.com/openstack/designate

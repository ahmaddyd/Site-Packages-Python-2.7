# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4; encoding:utf8 -*-
#
# Copyright 2002 Ben Escoto <ben@emerose.org>
# Copyright 2007 Kenneth Loafman <kenneth@loafman.com>
# Copyright 2011 Henrique Carvalho Alves <hcarvalhoalves@gmail.com>
#
# This file is part of duplicity.
#
# Duplicity is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.
#
# Duplicity is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with duplicity; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

import duplicity.backend
from duplicity import config

if config.s3_use_multiprocessing:
    from ._boto_multi import BotoBackend
else:
    from ._boto_single import BotoBackend

duplicity.backend.register_backend(u"gs", BotoBackend)
duplicity.backend.register_backend(u"s3", BotoBackend)
duplicity.backend.register_backend(u"s3+http", BotoBackend)
duplicity.backend.uses_netloc.extend([u's3'])
# s3 is also implemented by the newer boto3 backend now
duplicity.backend.register_backend(u"boto+s3", BotoBackend)
duplicity.backend.uses_netloc.extend([u'boto+s3'])

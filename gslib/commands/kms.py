# -*- coding: utf-8 -*-
# Copyright 2013 Google Inc. All Rights Reserved.
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
"""This module provides the kms command to gsutil."""

from __future__ import absolute_import
from __future__ import print_function

import getopt
import re
import time
import uuid

from gslib import metrics
from gslib.cloud_api import AccessDeniedException
from gslib.cloud_api import NotFoundException
from gslib.cloud_api import PublishPermissionDeniedException
from gslib.command import Command
from gslib.command import NO_MAX
from gslib.command_argument import CommandArgument
from gslib.cs_api_map import ApiSelector
from gslib.exception import CommandException
from gslib.help_provider import CreateHelpText
from gslib.project_id import PopulateProjectId
from gslib.kms_api import KmsApi
from gslib.storage_url import StorageUrlFromString
from gslib.third_party.kms_apitools.cloudkms_v1_messages import Binding
from gslib.third_party.storage_apitools import storage_v1_messages as apitools_messages

#from gslib.third_party.pubsub_apitools.pubsub_v1_messages import Binding


# Cloud KMS commands

_AUTHORIZE_SYNOPSIS = """
  gsutil kms authorize [-p proj_id] -k kms_key
"""

_ENCRYPTION_SYNOPSIS = """
  gsutil kms encryption [(-c|[-k kms_key])] bucket_url
"""

_SERVICEACCOUNT_SYNOPSIS = """
  gsutil kms serviceaccount [-p proj_id]
"""

_SYNOPSIS = (
  _AUTHORIZE_SYNOPSIS +
  _ENCRYPTION_SYNOPSIS.lstrip('\n') +
  _SERVICEACCOUNT_SYNOPSIS.lstrip('\n') +
  '\n')

_AUTHORIZE_DESCRIPTION = """
<B>AUTHORIZE</B>
  The authorize sub-command ensures that the default project (or a supplied
  project) has a service account created for it, then adds appropriate 
  encrypt/decrypt permissions to Cloud KMS resources such that GCS
  can write and read Cloud KMS-encrypted objects.
  
  <B>Examples</B>
  
  Authorize the default project to use a Cloud KMS key:
  
    gsutil kms authorize -k /projects/key-project/locations/global/keyrings/key-ring/keys/my-key
    
  Authorize my-project to use a Cloud KMS key:
  
    gsutil kms authorize -p my-project -k /projects/key-project/locations/global/keyrings/key-ring/keys/my-key
"""

_ENCRYPTION_DESCRIPTION = """
<B>ENCRYPTION</B>
  The encryption sub-command is used to set, display, or clear the KMS key
  that will be used by default to encrypt newly written objects in a bucket.
  
  <B>Examples</B>
  
  Set a KMS key to be used by default to encrypt newly written objects:
  
    gsutil kms encryption -k /projects/gcskms-guide-keys/locations/global/keyrings/guideKeyRing/key/guideKey gs://my_bucket
    
  Show the KMS key used by default to encrypt objects in a bucket, if any:
  
    gsutil kms encryption gs://my_bucket
    
  Clear the KMS key so newly written objects will not be encrypted:
  
    gsutil kms encryption -c gs://my_bucket
"""

_SERVICEACCOUNT_DESCRIPTION = """
<B>SERVICEACCOUNT</B>
  The serviceaccount sub-command displays the service account associated
  with the default project, or with a specified project.
  
  <B>Examples</B>
  
  Show the service account for the default project:
  
    gsutil kms serviceaccount
    
  Show the service account for my-project:
  
    gsutil kms serviceaccount -p my-project
"""

_DESCRIPTION = """
  The kms command is used to configure GCS and KMS resources to support 
  encryption of GCS objects with Cloud KMS keys.
  
<B>CLOUD KMS</B>

  These kms sub-commands deal with configuring GCS's integration with Cloud KMS.
  
""" + (_AUTHORIZE_SYNOPSIS +
       _ENCRYPTION_SYNOPSIS.lstrip('\n') +
       _SERVICEACCOUNT_SYNOPSIS.lstrip('\n'))

_DETAILED_HELP_TEXT = CreateHelpText(_SYNOPSIS, _DESCRIPTION)

_authorize_help_text = (
    CreateHelpText(_AUTHORIZE_SYNOPSIS, _AUTHORIZE_DESCRIPTION))
_encryption_help_text = (
    CreateHelpText(_ENCRYPTION_SYNOPSIS, _ENCRYPTION_DESCRIPTION))
_serviceaccount_help_text = (
    CreateHelpText(_SERVICEACCOUNT_SYNOPSIS, _SERVICEACCOUNT_DESCRIPTION))

PAYLOAD_FORMAT_MAP = {
    'none': 'NONE',
    'json': 'JSON_API_V1'
}

class KmsCommand(Command):
  """Implements of gsutil kms command."""
  
  command_spec = Command.CreateCommandSpec(
    'kms',
    command_name_aliases=[
        'authorize', 'encryption', 'serviceaccount'],
    usage_synopsis=_SYNOPSIS,
    min_args=0,
    max_args=NO_MAX,
    supported_sub_args='ck:p:',
    file_url_ok=False,
    provider_url_ok=False,
    urls_start_arg=1,
    gs_api_support=[ApiSelector.JSON],
    gs_default_api=ApiSelector.JSON,
    argparse_arguments={
        'authorize': [
        ],
        'encryption': [
            CommandArgument.MakeNCloudBucketURLsArgument(1)
        ],
        'serviceaccount': [
        ],
    }
  )
    # Help specification. See help_provider.py for documentation.
  help_spec = Command.HelpSpec(
      help_name='kms',
      help_name_aliases=['authorize', 'serviceaccount'],
      help_type='command_help',
      help_one_line_summary='Configure Cloud KMS integration',
      help_text=_DETAILED_HELP_TEXT,
      subcommand_help_text={
          'authorize': _authorize_help_text,
          'encryption': _encryption_help_text,
          'serviceaccount': _serviceaccount_help_text},
  )

  def _GatherSubOptions(self):
    self.CheckArguments()
    self.clear_kms_key = False
    self.kms_key = None
    
    # Determine the project, either from the provided buckets or the default
    if self.sub_opts:
      for o, a in self.sub_opts:
        if o == '-p':
          self.project_id = a
        elif o == '-k':
          self.kms_key = a
        elif o == '-c':
          self.clear_kms_key = True
    if not self.project_id:
      self.project_id = PopulateProjectId(None)
      
  def _AuthorizeProject(self, project_id, kms_key):
    # Request the service account for that project, which might create it
    service_account = self.gsutil_api.GetProjectServiceAccount(
        project_id, provider='gs').email_address
    
    kms_api = KmsApi(logger = self.logger)
    
    self.logger.debug('Getting IAM policy for %s', kms_key)    
    policy = kms_api.GetKeyIamPolicy(kms_key)
    self.logger.debug('Current policy is %s', policy)
    
    # Check if the required binding is already present
    binding = Binding(role='roles/cloudkms.cryptoKeyEncrypterDecrypter',
                      members=['serviceAccount:%s' % service_account])
    if binding not in policy.bindings:
      policy.bindings.append(binding)
      kms_api.SetKeyIamPolicy(kms_key, policy)
      return service_account
    else:
      return None
    
  def _Authorize(self):
    self._GatherSubOptions()
    if not self.kms_key:
      raise CommandException('%s %s requires a key to be specified with -k' % 
                             (self.command_name, self.subcommand_name))
    
    service_account = self._AuthorizeProject(self.project_id, self.kms_key) 
    if service_account:
      print('%s is now authorized to encrypt and decrypt with %s' % 
      (self.project_id, kms_key))
    else:
      self.logger.debug('GCS already has encrypt/decrypt permission on %s.', 
                        kms_key)
    return 0
  
  def _Encryption(self):
    self._GatherSubOptions()
    
    
    # Determine the project from the provided bucket
    bucket_arg = self.args[-1]
    bucket_url = StorageUrlFromString(bucket_arg)
    if not bucket_url.IsCloudUrl() or not bucket_url.IsBucket():
      raise CommandException(
          "%s %s requires a GCS bucket name, but got '%s'" %
          (self.command_name, self.subcommand_name, bucket_arg))
    if bucket_url.scheme != 'gs':
      raise CommandException(
          'The %s command can only be used with gs:// bucket URLs.' %
          self.command_name)
    bucket_name = bucket_url.bucket_name
    bucket_metadata = self.gsutil_api.GetBucket(
        bucket_name,
        fields=['projectNumber','encryption'],
        provider=bucket_url.scheme)

    if self.clear_kms_key:
      bucket_metadata.encryption = apitools_messages.Bucket.EncryptionValue()
      self.gsutil_api.PatchBucket(bucket_name, bucket_metadata, 
                                  fields=['encryption'], 
                                  provider=bucket_url.scheme)
      return 0
    
    if not self.kms_key:
      if bucket_metadata.encryption:
        print ('Bucket %s has default encryption key %s' % 
               (bucket_name, bucket_metadata.encryption.defaultKmsKeyName))
      else:
        print ('Bucket %s has no default encryption key' % bucket_name)
      return 0

    kms_key = self.kms_key    
    bucket_project_number = bucket_metadata.projectNumber
    encryption = apitools_messages.Bucket.EncryptionValue(
        defaultKmsKeyName=kms_key)
    bucket_metadata.encryption = encryption
    service_account = self._AuthorizeProject(bucket_project_number, kms_key) 
    if service_account:
      print('%s service account %s is now authorized to use %s' % 
            (bucket_name, service_account, kms_key))
    self.gsutil_api.PatchBucket(bucket_name, bucket_metadata, 
                                fields=['encryption'], 
                                provider=bucket_url.scheme)
        
    return 0
  
  def _ServiceAccount(self):
    self.CheckArguments()
    if not self.args:
      self.args = ['gs://']
    if self.sub_opts:
      for o, a in self.sub_opts:
        if o == '-p':
          self.project_id = a
          
    if not self.project_id:
      self.project_id = PopulateProjectId(None)
      
    # Determine the project, either from the provided buckets or the default
    # Request the service account for that project, which might create it
    self.logger.debug('Checking service account for project %s', 
                      self.project_id)
    
    service_account = self.gsutil_api.GetProjectServiceAccount(
        self.project_id, provider='gs').email_address
    
    print (service_account)
    
    return 0

  def _RunSubCommand(self, func):
    try:
      (self.sub_opts, self.args) = getopt.getopt(
          self.args, self.command_spec.supported_sub_args)
      # Commands with both suboptions and subcommands need to reparse for
      # suboptions, so we log again.
      metrics.LogCommandParams(sub_opts=self.sub_opts)
      return func(self)
    except getopt.GetoptError:
      self.RaiseInvalidArgumentException()

  SUBCOMMANDS = {
      'authorize': _Authorize,
      'encryption': _Encryption,
      'serviceaccount': _ServiceAccount}

  def RunCommand(self):
    """Command entry point for the kms command."""
    self.subcommand_name = self.args.pop(0)
    if self.subcommand_name in KmsCommand.SUBCOMMANDS:
      metrics.LogCommandParams(subcommands=[self.subcommand_name])
      return self._RunSubCommand(KmsCommand.SUBCOMMANDS[
          self.subcommand_name])
    else:
      raise CommandException('Invalid subcommand "%s" for the %s command.' %
                             (self.subcommand_name, self.command_name))

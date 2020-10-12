import inspect
import tempfile
import traceback
import xml.etree.ElementTree as ET
from tempfile import NamedTemporaryFile

import jarray

import json
import platform
import subprocess

from java.util.logging import Level
from java.io import File
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager


def calc_last_time_active(xml_element, filename):
    """
    Calculate the absolute time (in EPOCH) when an event was active for the last time.
    :param xml_element: The element containing an lastTimeActive attribute
    :param filename: A filename where the name contains digits only, representing the creation time in EPOCH.
    :return: The EPOCH representation of the time an event was active for the last time.
    """
    if 'lastTimeActive' in xml_element.keys():
        relative_last_time_active = int(xml_element.attrib['lastTimeActive'])

        # Some events show the last_time_active as EPOCH already, which is indicated by starting with a minus sign
        if relative_last_time_active < 0:
            last_time_active = abs(relative_last_time_active)

        # Otherwise we need to add the filename (which is the start time in EPOCH)
        # to the relative time (represented in ms)
        else:
            last_time_active = int(filename) + relative_last_time_active
        return last_time_active


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the anlaysis.
class AndroidUsagestatsFactory(IngestModuleFactoryAdapter):
    moduleName = "Android Usagestats"
    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Android usagestats parser to add recorded usage events to the autopsy timeline."

    def getModuleVersionNumber(self):
        return "2020.10.11"

    # Return true if module wants to get called for each file
    def isFileIngestModuleFactory(self):
        return True

    # can return null if isFileIngestModuleFactory returns false
    def createFileIngestModule(self, ingestOptions):
        return AutopsyUsagestatsIngestModule()


# File-level ingest module.  One gets created per thread.
# TODO: Rename this to something more specific. Could just remove "Factory" from above name.
# Looks at the attributes of the passed in file.
class AutopsyUsagestatsIngestModule(FileIngestModule):
    _logger = Logger.getLogger(AndroidUsagestatsFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    # Setup and configuration
    def startUp(self, context):
        self.filesFound = 0

        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException(IngestModule(), "Oh No!")
        pass

    def process(self, datasource):
        try:
            def getBlackboardAtt(label, value):
                return BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.fromLabel(label).getTypeID(),
                                           AndroidUsagestatsFactory.moduleName, value)

            # Skip everything that is not a file
            if ((datasource.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or
                    (datasource.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or
                    (not datasource.isFile())):
                return IngestModule.ProcessResult.OK

            # The usagestats files are named after their EPOCH timestamp and found in directory:
            # /data/system/usagestats/
            # In there you'll find directories called either /monthly or /daily or /weekly or /yearly
            # In these directories the usagestats files are found.
            fileManager = Case.getCurrentCase().getServices().getFileManager()
            monthly = fileManager.findFiles(datasource, "monthly%")
            daily = fileManager.findFiles(datasource, "daily%")
            weekly = fileManager.findFiles(datasource, "weekly%")
            yearly = fileManager.findFiles(datasource, "yearly%")

            # For an example, we will flag files with .txt in the name and make a blackboard artifact.
            if datasource.getName().isnumeric():

                self.log(Level.INFO, "Found a usagestats file: " + datasource.getLocalPath())
                self.filesFound += 1
                # get an input buffer
                # datasource_size = datasource.getSize()
                # self.log(Level.INFO, "Size: " + str(datasource_size))
                # datasource_contents = jarray.zeros(datasource_size, 'b')
                # datasource.read(datasource_contents, 0, datasource_size)
                # datasource.close()

                temporary = tempfile.NamedTemporaryFile()
                ContentUtils.writeToFile(datasource, File(temporary.name))
                # temporary.write(datasource_contents)

                try:
                    tree = ET.parse(temporary.name)
                    tree_root = tree.getroot()

                except ET.ParseError:
                    self.log(Level.WARNING, "Can't parse this file as XML with xml.etree.ElementTree, skipping")
                    self.log(Level.WARNING, "For file: " + temporary.name)
                    return

                # We have sucessfully parsed the usagestats xml.
                # So continue processing

                # TODO Find out how to access Sleuth Kit's database and insert these events
                # These are the basic types
                # https://github.com/sleuthkit/sleuthkit/blob/c5f90e4680868d4efd82743a45e8497ea52f320f/bindings/java/src/org/sleuthkit/datamodel/CaseDatabaseFactory.java#L388-L395
                #              WHEN '1' THEN 'MOVE_TO_FOREGROUND'
                #              WHEN '2' THEN 'MOVE_TO_BACKGROUND'
                #              WHEN '5' THEN 'CONFIGURATION_CHANGE'
                #              WHEN '7' THEN 'USER_INTERACTION'
                #              WHEN '8' THEN 'SHORTCUT_INVOCATION'
                # MAX(event_type_id) + 1 om database-onafhankelijk nieuwe id's te vinden
                # Check the database for presence of our types. If not insert them.
                # For anything else, make up a string like 'ANDROID_EVENT_777'
                # INSERT INTO tsk_event_types (event_type_id, display_name, super_type_id)
                # VALUES (?, ?, ?)

                for xml_element in tree_root:
                    for child in xml_element:
                        all_attributes = json.dumps(child.attrib)
                        usage_type = xml_element.tag
                        # If the attribute exists in this xml element, fetch its value. Otherwise set to ''

                        last_active_time = calc_last_time_active(child, datasource.getName())
                        package = child.attrib.get('package', '')
                        time_active = child.attrib.get('timeActive', 0)
                        app_launch = child.attrib.get('appLaunchCount', '')
                        type_class = child.attrib.get('class', '')
                        type_type = child.attrib.get('type', '')

                        art = datasource.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_TL_EVENT)
                        # TODO placeholders
                        # art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TL_EVENT_TYPE, AndroidUsagestatsFactory.moduleName, 26))
                        # art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME, AndroidUsagestatsFactory.moduleName, int(time_active)))  # in seconds
                        # art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DESCRIPTION, AndroidUsagestatsFactory.moduleName, package))
                        art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TL_EVENT_TYPE, AndroidUsagestatsFactory.moduleName, 3))
                        art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME, AndroidUsagestatsFactory.moduleName, int(time_active)))  # in seconds
                        art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DESCRIPTION, AndroidUsagestatsFactory.moduleName, package))

        # TODO: remove after testing
        except Exception as e:
            with open('/tmp/traceback_autopsy.txt', 'w') as w:
                w.write(str(e))
                w.write('\n')
                w.write(traceback.format_exc())

        IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(AndroidUsagestatsFactory.moduleName, BlackboardArtifact.ARTIFACT_TYPE.TSK_TL_EVENT, None))

        return IngestModule.ProcessResult.OK

    # Where any shutdown code is run and resources are freed.
    # TODO: Add any shutdown code that you need here.
    def shutDown(self):
        # As a final part of this example, we'll send a message to the ingest inbox with the number of files found (in this thread)
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, AndroidUsagestatsFactory.moduleName,
            str(self.filesFound) + " files found")
        ingestServices = IngestServices.getInstance().postMessage(message)

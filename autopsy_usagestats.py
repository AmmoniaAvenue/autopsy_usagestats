import inspect
import traceback
import json
import platform
import subprocess

from java.util.logging import Level
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
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the anlaysis.
class AndroidUsagestatsFactory(IngestModuleFactoryAdapter):
    moduleName = "Android Usagestats"

    `def getModuleDisplayName(self):
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
            # Skip everything that is not a file
            if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or
                    (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or
                    (not file.isFile())):
                return IngestModule.ProcessResult.OK
            # The usagestats files are named after their EPOCH timestamp and found in directory:
            # /data/system/usagestats/
            # In there you'll find directories called either /monthly or /daily or /weekly or /yearly
            # In these directories the usagestats files are found.
            fileManager = Case.getCurrentCase().getServices().getFileManager()
            files = fileManager.findFiles(datasource, "usagestats%")
            numFiles = len(files)
            self.log(Level.INFO, "found " + str(numFiles) + " files")

            # For an example, we will flag files with .txt in the name and make a blackboard artifact.
            if file.getName().lower().endswith(".txt"):

                self.log(Level.INFO, "Found a text file: " + file.getName())
                self.filesFound += 1

            # # Make an artifact on the blackboard.  TSK_INTERESTING_FILE_HIT is a generic type of
            # # artifact.  Refer to the developer docs for other examples.
            # art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            # att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(),
            #                           AndroidUsagestatsFactory.moduleName, "Text Files")
            # art.addAttribute(att)
            #
            # # Fire an event to notify the UI and others that there is a new artifact
            # IngestServices.getInstance().fireModuleDataEvent(
            #     ModuleDataEvent(AndroidUsagestatsFactory.moduleName,
            #                     BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None));
            #
            # # For the example (this wouldn't be needed normally), we'll query the blackboard for data that was added
            # # by other modules. We then iterate over its attributes.  We'll just print them, but you would probably
            # # want to do something with them.
            # artifactList = file.getArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            # for artifact in artifactList:
            #     attributeList = artifact.getAttributes();
            #     for attrib in attributeList:
            #         self.log(Level.INFO, attrib.toString())
            #
            # # To further the example, this code will read the contents of the file and count the number of bytes
            # inputStream = ReadContentInputStream(file)
            # buffer = jarray.zeros(1024, "b")
            # totLen = 0
            # len = inputStream.read(buffer)
            # while (len != -1):
            #     totLen = totLen + len
            #     len = inputStream.read(buffer)

        # TODO: remove after testing
        except Exception as e:
            with open('/home/ginger/Deskrop/traceback_autopsy.txt', 'w') as w:
                w.write(str(e))
                w.write('\n')
                w.write(traceback.format_exc())

        return IngestModule.ProcessResult.OK

    # Where any shutdown code is run and resources are freed.
    # TODO: Add any shutdown code that you need here.
    def shutDown(self):
        # As a final part of this example, we'll send a message to the ingest inbox with the number of files found (in this thread)
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, AndroidUsagestatsFactory.moduleName,
            str(self.filesFound) + " files found")
        ingestServices = IngestServices.getInstance().postMessage(message)

import inspect
import json
import platform
import subprocess

if platform.system() == 'Java':  # Jython runtime imports
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



    # Factory that defines the name and details of the module and allows Autopsy
    # to create instances of the modules that will do the anlaysis.
    # TODO: Rename this to something more specific.  Search and replace for it because it is used a few times
    class AndroidUsagestatsFactory(IngestModuleFactoryAdapter):
        # TODO: give it a unique name.  Will be shown in module list, logs, etc.
        moduleName = "Sample file ingest Module"

        def getModuleDisplayName(self):
            return self.moduleName

        # TODO: Give it a description
        def getModuleDescription(self):
            return "Sample module that does X, Y, and Z."

        def getModuleVersionNumber(self):
            return "1.0"

        # Return true if module wants to get called for each file
        def isFileIngestModuleFactory(self):
            return True

        # can return null if isFileIngestModuleFactory returns false
        def createFileIngestModule(self, ingestOptions):
            return SampleJythonFileIngestModule()


    # File-level ingest module.  One gets created per thread.
    # TODO: Rename this to something more specific. Could just remove "Factory" from above name.
    # Looks at the attributes of the passed in file.
    class SampleJythonFileIngestModule(FileIngestModule):
        _logger = Logger.getLogger(SampleJythonFileIngestModuleFactory.moduleName)

        def log(self, level, msg):
            self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

        # Where any setup and configuration is done
        # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
        # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
        # TODO: Add any setup code that you need here.
        def startUp(self, context):
            self.filesFound = 0

            # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
            # raise IngestModuleException(IngestModule(), "Oh No!")
            pass

        # Where the analysis is done.  Each file will be passed into here.
        # The 'file' object being passed in is of type org.sleuthkit.datamodel.AbstractFile.
        # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
        # TODO: Add your analysis code in here.
        def process(self, file):
            # Skip non-files
            if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or
                    (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or
                    (file.isFile() == False)):
                return IngestModule.ProcessResult.OK

            # For an example, we will flag files with .txt in the name and make a blackboard artifact.
            if file.getName().lower().endswith(".txt"):

                self.log(Level.INFO, "Found a text file: " + file.getName())
                self.filesFound += 1

                # Make an artifact on the blackboard.  TSK_INTERESTING_FILE_HIT is a generic type of
                # artifact.  Refer to the developer docs for other examples.
                art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(),
                                          SampleJythonFileIngestModuleFactory.moduleName, "Text Files")
                art.addAttribute(att)

                # Fire an event to notify the UI and others that there is a new artifact
                IngestServices.getInstance().fireModuleDataEvent(
                    ModuleDataEvent(SampleJythonFileIngestModuleFactory.moduleName,
                                    BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None));

                # For the example (this wouldn't be needed normally), we'll query the blackboard for data that was added
                # by other modules. We then iterate over its attributes.  We'll just print them, but you would probably
                # want to do something with them.
                artifactList = file.getArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                for artifact in artifactList:
                    attributeList = artifact.getAttributes();
                    for attrib in attributeList:
                        self.log(Level.INFO, attrib.toString())

                # To further the example, this code will read the contents of the file and count the number of bytes
                inputStream = ReadContentInputStream(file)
                buffer = jarray.zeros(1024, "b")
                totLen = 0
                len = inputStream.read(buffer)
                while (len != -1):
                    totLen = totLen + len
                    len = inputStream.read(buffer)

            return IngestModule.ProcessResult.OK

        # Where any shutdown code is run and resources are freed.
        # TODO: Add any shutdown code that you need here.
        def shutDown(self):
            # As a final part of this example, we'll send a message to the ingest inbox with the number of files found (in this thread)
            message = IngestMessage.createMessage(
                IngestMessage.MessageType.DATA, SampleJythonFileIngestModuleFactory.moduleName,
                str(self.filesFound) + " files found")
            ingestServices = IngestServices.getInstance().postMessage(message)